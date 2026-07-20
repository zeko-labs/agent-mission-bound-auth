import { createPrivateKey, createPublicKey, sign as cryptoSign, verify as cryptoVerify } from "node:crypto";
import { id, sha256Hex } from "./digest.js";
import { isProductionProfile, isProductionStrictVerifier } from "./runtime.js";

export const DIGEST_HOLDER_PROOF_SCHEME = "digest-holder-proof-v1";
export const ED25519_HOLDER_PROOF_SCHEME = "ed25519-holder-proof-v1";
export const BROWSER_HELPER_ED25519_COMPAT_HOLDER_PROOF_SCHEME = "browser-helper-ed25519-pop-v1";

export function holderChallengeHash(eventBody) {
  return sha256Hex({
    missionIdHash: eventBody.missionIdHash,
    capabilityHash: eventBody.capabilityHash,
    policyHash: eventBody.policyHash,
    eventType: eventBody.eventType,
    action: eventBody.action,
    actionHash: eventBody.actionHash,
    targetDomainHash: eventBody.targetDomainHash,
    resourceHash: eventBody.resourceHash,
    paymentContextDigest: eventBody.paymentContextDigest,
    sideEffectId: eventBody.sideEffectId,
    idempotencyKey: eventBody.idempotencyKey,
    previousEventHash: eventBody.previousEventHash
  });
}

function keyObjectFromPrivateInput(input) {
  const key = input.privateKey ?? input.privateJwk;
  if (!key) return null;
  if (typeof key === "object" && key.type === "private") return key;
  if (typeof key === "object" && key.kty) return createPrivateKey({ key, format: "jwk" });
  return createPrivateKey(key);
}

function keyObjectFromPublicInput(input) {
  const key = input.publicKey ?? input.publicJwk;
  if (!key) return null;
  if (typeof key === "object" && key.type === "public") return key;
  if (typeof key === "object" && key.kty) return createPublicKey({ key, format: "jwk" });
  return createPublicKey(key);
}

function publicJwkFromHolderInput(input = {}) {
  if (input.publicJwk) return input.publicJwk;
  const publicKey = keyObjectFromPublicInput(input);
  if (publicKey) return publicKey.export({ format: "jwk" });
  const privateKey = keyObjectFromPrivateInput(input);
  if (!privateKey) return null;
  return createPublicKey(privateKey).export({ format: "jwk" });
}

function isEd25519Jwk(publicJwk) {
  return publicJwk?.kty === "OKP" && publicJwk?.crv === "Ed25519" && typeof publicJwk?.x === "string";
}

function holderKeyCommitmentFromInput(input = {}) {
  if (input.holderKeyCommitment) return input.holderKeyCommitment;
  const publicJwk = publicJwkFromHolderInput(input.holder ?? {});
  return publicJwk ? sha256Hex(publicJwk) : undefined;
}

export function buildHolderProof(eventBody, input = {}) {
  const messageHash = holderChallengeHash(eventBody);
  const scheme = input.scheme ?? DIGEST_HOLDER_PROOF_SCHEME;
  if (scheme !== DIGEST_HOLDER_PROOF_SCHEME && scheme !== ED25519_HOLDER_PROOF_SCHEME) {
    throw new Error(`Unsupported holder proof scheme:${scheme}.`);
  }
  if (scheme === ED25519_HOLDER_PROOF_SCHEME) {
    const publicJwk = publicJwkFromHolderInput(input);
    if (!publicJwk) {
      throw new Error("ed25519-holder-proof-v1 requires publicJwk or privateKey.");
    }
    if (!isEd25519Jwk(publicJwk)) {
      throw new Error("ed25519-holder-proof-v1 requires an Ed25519 public JWK.");
    }
    const privateKey = keyObjectFromPrivateInput(input);
    const signature = input.signature ?? (privateKey
      ? cryptoSign(null, Buffer.from(messageHash, "utf8"), privateKey).toString("base64url")
      : null);
    if (!signature) {
      throw new Error("ed25519-holder-proof-v1 requires signature or privateKey.");
    }
    return {
      scheme,
      keyThumbprint: input.keyThumbprint ?? sha256Hex(publicJwk),
      publicJwk,
      messageHash,
      signature
    };
  }

  return {
    scheme,
    keyThumbprint: input.keyThumbprint ?? eventBody.holderKeyCommitment,
    messageHash,
    signature: input.signature ?? sha256Hex({
      holderSecret: input.holderSecret ?? "local-holder-proof",
      messageHash
    })
  };
}

export function buildBoundaryEvent(input = {}) {
  const body = {
    version: "mission-bound-boundary-event-v1",
    missionIdHash: input.missionIdHash,
    capabilityHash: input.capabilityHash,
    policyHash: input.policyHash,
    eventType: input.eventType ?? input.action,
    action: input.action,
    actionHash: input.actionHash ?? sha256Hex(input.action ?? input.eventType),
    targetDomainHash: input.targetDomainHash ?? sha256Hex(input.targetDomain ?? "unknown-domain"),
    resourceHash: input.resourceHash ?? sha256Hex(input.resource ?? input.datasetId ?? "unknown-resource"),
    paymentContextDigest: input.paymentContextDigest ?? sha256Hex(input.paymentContext ?? "no-payment-context"),
    sideEffectId: input.sideEffectId ?? null,
    idempotencyKey: input.idempotencyKey ?? null,
    previousEventHash: input.previousEventHash ?? "GENESIS",
    observedAt: input.observedAt ?? new Date().toISOString(),
    expiresAt: input.expiresAt,
    holderKeyCommitment: holderKeyCommitmentFromInput(input)
  };
  const holderProof = input.holderProof ?? buildHolderProof(body, input.holder ?? {});
  const eventBody = {
    ...body,
    holderProof
  };
  return {
    ...eventBody,
    eventId: input.eventId ?? id("event", eventBody),
    eventHash: sha256Hex(eventBody)
  };
}

function verifyDigestHolderProof(holderProof, options = {}) {
  if (options.requireStrongHolderProof ?? isProductionProfile(options.env ?? process.env)) {
    return { valid: false, reason: "digest-holder-proof-v1 is not accepted for production holder proofs." };
  }
  const expected = sha256Hex({
    holderSecret: options.holderSecret ?? "local-holder-proof",
    messageHash: holderProof.messageHash
  });
  if (holderProof.signature !== expected) {
    return { valid: false, reason: "Digest holder proof signature is invalid." };
  }
  return { valid: true };
}

function verifyEd25519HolderProof(event, holderProof) {
  if (!holderProof.publicJwk) {
    return { valid: false, reason: "Ed25519 holder proof missing publicJwk." };
  }
  if (!isEd25519Jwk(holderProof.publicJwk)) {
    return { valid: false, reason: "Ed25519 holder proof requires an Ed25519 public JWK." };
  }
  const keyThumbprint = sha256Hex(holderProof.publicJwk);
  if (holderProof.keyThumbprint !== keyThumbprint) {
    return { valid: false, reason: "Ed25519 holder proof key thumbprint mismatch." };
  }
  if (event.holderKeyCommitment !== keyThumbprint) {
    return { valid: false, reason: "Ed25519 holder proof is not bound to the event holder key commitment." };
  }
  try {
    const publicKey = createPublicKey({ key: holderProof.publicJwk, format: "jwk" });
    const ok = cryptoVerify(
      null,
      Buffer.from(holderProof.messageHash, "utf8"),
      publicKey,
      Buffer.from(holderProof.signature, "base64url")
    );
    if (!ok) return { valid: false, reason: "Ed25519 holder proof signature is invalid." };
    return { valid: true };
  } catch (error) {
    return { valid: false, reason: error instanceof Error ? error.message : "Ed25519 holder proof verification failed." };
  }
}

function verifyCompatibilityHolderProof(event, holderProof, options = {}) {
  if (isProductionStrictVerifier(options, options.env ?? process.env)) {
    return { valid: false, reason: "Compatibility holder proofs are not accepted in production_strict verifier mode." };
  }
  if (!holderProof.publicJwk) {
    return { valid: false, reason: "Compatibility holder proof missing publicJwk." };
  }
  if (!isEd25519Jwk(holderProof.publicJwk)) {
    return { valid: false, reason: "Compatibility holder proof requires an Ed25519 public JWK." };
  }
  const keyThumbprint = sha256Hex(holderProof.publicJwk);
  if (holderProof.keyThumbprint !== keyThumbprint) {
    return { valid: false, reason: "Compatibility holder proof key thumbprint mismatch." };
  }
  if (event.holderKeyCommitment !== keyThumbprint) {
    return { valid: false, reason: "Compatibility holder proof is not bound to the event holder key commitment." };
  }
  try {
    const signedChallengeHash = holderProof.appChallengeHash ?? holderProof.compatibilityChallengeHash ?? holderProof.messageHash;
    const publicKey = createPublicKey({ key: holderProof.publicJwk, format: "jwk" });
    const ok = cryptoVerify(
      null,
      Buffer.from(signedChallengeHash, "utf8"),
      publicKey,
      Buffer.from(holderProof.signature, "base64url")
    );
    if (!ok) return { valid: false, reason: "Compatibility holder proof signature is invalid." };
    return {
      valid: true,
      compatibilityMode: true,
      signedChallengeHash
    };
  } catch (error) {
    return { valid: false, reason: error instanceof Error ? error.message : "Compatibility holder proof verification failed." };
  }
}

export function verifyHolderProof(event, options = {}) {
  const holderProof = event.holderProof;
  if (!holderProof?.messageHash) {
    return { valid: false, reason: "Boundary event missing holder proof message hash." };
  }
  const { eventId: _eventId, eventHash: _eventHash, ...body } = event;
  if (holderProof.messageHash !== holderChallengeHash(body)) {
    return { valid: false, reason: "Boundary event holder proof is not bound to this action context." };
  }
  if (holderProof.scheme === ED25519_HOLDER_PROOF_SCHEME) {
    return verifyEd25519HolderProof(event, holderProof);
  }
  if (holderProof.scheme === BROWSER_HELPER_ED25519_COMPAT_HOLDER_PROOF_SCHEME) {
    return verifyCompatibilityHolderProof(event, holderProof, options);
  }
  if (!holderProof.scheme || holderProof.scheme === DIGEST_HOLDER_PROOF_SCHEME) {
    return verifyDigestHolderProof(holderProof, options);
  }
  return { valid: false, reason: `Unsupported holder proof scheme:${holderProof.scheme}.` };
}

export function verifyBoundaryEvent(event, options = {}) {
  if (!event || typeof event !== "object") {
    return { valid: false, reason: "Missing boundary event." };
  }
  if (event.version !== "mission-bound-boundary-event-v1") {
    return { valid: false, reason: "Unsupported boundary event version." };
  }
  const { eventId, eventHash, ...body } = event;
  if (eventId !== id("event", body)) {
    return { valid: false, reason: "Boundary event id mismatch." };
  }
  if (eventHash !== sha256Hex(body)) {
    return { valid: false, reason: "Boundary event hash mismatch." };
  }
  if (options.previousEventHash && event.previousEventHash !== options.previousEventHash) {
    return { valid: false, reason: "Boundary event previousHash mismatch." };
  }
  if (options.missionIdHash && event.missionIdHash !== options.missionIdHash) {
    return { valid: false, reason: "Boundary event missionIdHash mismatch." };
  }
  if (options.capabilityHash && event.capabilityHash !== options.capabilityHash) {
    return { valid: false, reason: "Boundary event capabilityHash mismatch." };
  }
  if (options.policyHash && event.policyHash !== options.policyHash) {
    return { valid: false, reason: "Boundary event policyHash mismatch." };
  }
  if (options.allowedActions && !options.allowedActions.includes(event.action)) {
    return { valid: false, reason: `Boundary event action not allowed: ${event.action}.` };
  }
  if (options.allowedDomainHashes && !options.allowedDomainHashes.includes(event.targetDomainHash)) {
    return { valid: false, reason: "Boundary event target domain not allowed." };
  }
  if (isProductionStrictVerifier(options, options.env ?? process.env)) {
    if (!event.expiresAt) {
      return { valid: false, reason: "production_strict boundary events require expiresAt." };
    }
    if (!event.idempotencyKey) {
      return { valid: false, reason: "production_strict boundary events require idempotencyKey." };
    }
    if (!event.holderKeyCommitment) {
      return { valid: false, reason: "production_strict boundary events require holderKeyCommitment." };
    }
  }
  if (!options.allowExpired && event.expiresAt) {
    const expiry = Date.parse(event.expiresAt);
    if (Number.isNaN(expiry) || expiry <= Date.now()) {
      return { valid: false, reason: "Boundary event expired or has invalid expiry." };
    }
  }
  const holderProof = verifyHolderProof(event, options);
  if (!holderProof.valid) return holderProof;
  return { valid: true, eventHash, eventId };
}

export function verifyTraceChain(events = [], options = {}) {
  if (!Array.isArray(events) || events.length === 0) {
    return { valid: false, reason: "Trace must contain at least one boundary event." };
  }

  let previousEventHash = options.initialPreviousEventHash ?? "GENESIS";
  for (const event of events) {
    const verified = verifyBoundaryEvent(event, {
      ...options,
      previousEventHash
    });
    if (!verified.valid) {
      return { ...verified, eventHash: event?.eventHash };
    }
    previousEventHash = event.eventHash;
  }

  const latestEventHash = events.at(-1).eventHash;
  return {
    valid: true,
    eventCount: events.length,
    traceHash: sha256Hex({ events: events.map((event) => event.eventHash) }),
    latestEventHash
  };
}
