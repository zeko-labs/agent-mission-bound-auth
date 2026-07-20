import { id, randomSalt, sha256Hex } from "./digest.js";

export const BOUNDARY_EVENT_VOCABULARY = Object.freeze({
  version: "mission-bound-action-vocabulary-v1",
  actions: [
    "browser.open",
    "page.read",
    "form.fill",
    "vault.read",
    "cart.prepare",
    "payment.prepare",
    "payment.authorize",
    "private_compute.run",
    "email.draft",
    "email.send",
    "external_agent.hire",
    "external_app.side_effect",
    "final_submit",
    "x402.payment_offer",
    "x402.pay",
    "x402.settle",
    "zeko.receipt.anchor"
  ]
});

export const MISSION_PROOF_STATES = Object.freeze([
  "capability_issued",
  "holder_bound",
  "funds_reserved",
  "mission_started",
  "boundary_events_recorded",
  "receipt_created",
  "proof_prepared",
  "proof_verified",
  "anchor_prepared",
  "anchored",
  "settlement_release_allowed",
  "settled",
  "disputed",
  "expired",
  "failed"
]);

export const SETTLEMENT_DECISIONS = Object.freeze([
  "not_ready",
  "release_allowed",
  "release_denied",
  "manual_review",
  "duplicate_payment",
  "expired_authorization",
  "policy_violation"
]);

function optional(value) {
  return value === undefined ? undefined : value;
}

function withoutUndefined(value) {
  return Object.fromEntries(Object.entries(value).filter(([, entry]) => entry !== undefined));
}

function isSubset(subset = [], superset = []) {
  const allowed = new Set(superset);
  return subset.every((item) => allowed.has(item));
}

function numericSpend(value) {
  const parsed = Number.parseFloat(String(value ?? "0"));
  return Number.isFinite(parsed) ? parsed : NaN;
}

function capabilityBodyFrom(input = {}) {
  return withoutUndefined({
    version: "mission-bound-capability-v1",
    issuer: input.issuer ?? "agent-mission-bound-auth",
    audience: input.audience ?? "mission-verifier",
    principalHash: input.principalHash ?? sha256Hex(input.principal ?? "unknown-principal"),
    agentId: input.agentId,
    runtimeId: input.runtimeId ?? input.agentId,
    holderKeyCommitment: input.holderKeyCommitment ?? sha256Hex(input.holderPublicKey ?? input.agentId ?? "unknown-holder"),
    missionId: input.missionId,
    missionIdHash: input.missionIdHash ?? sha256Hex(input.missionId ?? "unknown-mission"),
    allowedDomains: input.allowedDomains ?? [],
    allowedActions: input.allowedActions ?? input.allowedTools ?? [],
    dataScopes: input.dataScopes ?? input.datasetScopes ?? [],
    paymentRails: input.paymentRails ?? input.allowedRails ?? [],
    maxSpendUsd: input.maxSpendUsd ?? "0.00",
    expiresAt: input.expiresAt,
    jti: input.jti,
    nullifierSeed: input.nullifierSeed,
    settlementReleaseCondition: input.settlementReleaseCondition ?? "valid_receipt_root_and_payment_context",
    previousCapabilityHash: optional(input.previousCapabilityHash),
    renewalCounter: optional(input.renewalCounter),
    renewalReason: optional(input.renewalReason),
    replacedJti: optional(input.replacedJti)
  });
}

export function buildMissionPolicy(input = {}) {
  const policy = {
    version: "mission-bound-policy-v1",
    missionId: input.missionId,
    task: input.task,
    allowedDomains: input.allowedDomains ?? [],
    allowedActions: input.allowedActions ?? input.allowedTools ?? [],
    dataScopes: input.dataScopes ?? input.datasetScopes ?? [],
    paymentRails: input.paymentRails ?? input.allowedRails ?? [],
    maxSpendUsd: input.maxSpendUsd ?? "0.00",
    expiresAt: input.expiresAt,
    checkpoints: input.checkpoints ?? [],
    constraints: input.constraints ?? {},
    receiptRequirements: input.receiptRequirements ?? [
      "capabilityHash",
      "policyHash",
      "traceHash",
      "paymentContextDigest",
      "nullifier",
      "anchorReference"
    ]
  };

  return {
    ...policy,
    policyHash: sha256Hex(policy)
  };
}

export function buildMissionCapability(input = {}) {
  const expiresAt = input.expiresAt ?? new Date(Date.now() + 20 * 60 * 1000).toISOString();
  const nullifierSeed = input.nullifierSeed ?? randomSalt(24);
  const body = capabilityBodyFrom({
    ...input,
    expiresAt,
    jti: input.jti ?? id("jti", { missionId: input.missionId, agentId: input.agentId, nullifierSeed }),
    nullifierSeed
  });

  const capabilityId = input.capabilityId ?? id("capability", body);
  const capabilityHash = sha256Hex(body);
  return {
    ...body,
    capabilityId,
    capabilityHash,
    nullifier: sha256Hex({
      capabilityId,
      capabilityHash,
      missionIdHash: body.missionIdHash,
      nullifierSeed,
      settlementReleaseCondition: body.settlementReleaseCondition
    })
  };
}

export function renewMissionCapability(previousCapability, input = {}) {
  const previous = verifyCapability(previousCapability, { allowExpired: true });
  if (!previous.valid) {
    throw new Error(previous.reason);
  }
  const renewalCounter = input.renewalCounter ?? Number(previousCapability.renewalCounter ?? 0) + 1;
  const nullifierSeed = input.nullifierSeed ?? randomSalt(24);
  const nextInput = {
    issuer: previousCapability.issuer,
    audience: previousCapability.audience,
    principalHash: previousCapability.principalHash,
    agentId: previousCapability.agentId,
    runtimeId: input.runtimeId ?? previousCapability.runtimeId,
    holderKeyCommitment: previousCapability.holderKeyCommitment,
    missionId: previousCapability.missionId,
    missionIdHash: previousCapability.missionIdHash,
    allowedDomains: input.allowedDomains ?? previousCapability.allowedDomains ?? [],
    allowedActions: input.allowedActions ?? previousCapability.allowedActions ?? [],
    dataScopes: input.dataScopes ?? previousCapability.dataScopes ?? [],
    paymentRails: input.paymentRails ?? previousCapability.paymentRails ?? [],
    maxSpendUsd: input.maxSpendUsd ?? previousCapability.maxSpendUsd,
    expiresAt: input.expiresAt ?? new Date(Date.now() + 20 * 60 * 1000).toISOString(),
    jti: input.jti ?? id("jti", {
      missionIdHash: previousCapability.missionIdHash,
      agentId: previousCapability.agentId,
      previousCapabilityHash: previousCapability.capabilityHash,
      renewalCounter,
      nullifierSeed
    }),
    nullifierSeed,
    settlementReleaseCondition: input.settlementReleaseCondition ?? previousCapability.settlementReleaseCondition,
    previousCapabilityHash: previousCapability.capabilityHash,
    renewalCounter,
    renewalReason: input.renewalReason ?? "short_lived_capability_renewal",
    replacedJti: previousCapability.jti
  };
  const renewedCapability = buildMissionCapability(nextInput);
  const renewal = buildCapabilityRenewal({
    previousCapability,
    renewedCapability,
    renewalCounter,
    renewalReason: nextInput.renewalReason,
    issuedAt: input.issuedAt
  });
  return { capability: renewedCapability, renewal };
}

export function buildCapabilityRenewal(input = {}) {
  const previousCapability = input.previousCapability;
  const renewedCapability = input.renewedCapability ?? input.capability;
  const body = {
    version: "mission-bound-capability-renewal-v1",
    missionIdHash: input.missionIdHash ?? previousCapability?.missionIdHash ?? renewedCapability?.missionIdHash,
    previousCapabilityHash: input.previousCapabilityHash ?? previousCapability?.capabilityHash,
    renewedCapabilityHash: input.renewedCapabilityHash ?? renewedCapability?.capabilityHash,
    holderKeyCommitment: input.holderKeyCommitment ?? previousCapability?.holderKeyCommitment ?? renewedCapability?.holderKeyCommitment,
    previousJti: input.previousJti ?? previousCapability?.jti,
    renewedJti: input.renewedJti ?? renewedCapability?.jti,
    renewalCounter: input.renewalCounter ?? renewedCapability?.renewalCounter,
    renewalReason: input.renewalReason ?? renewedCapability?.renewalReason ?? "short_lived_capability_renewal",
    issuedAt: input.issuedAt ?? new Date().toISOString(),
    expiresAt: input.expiresAt ?? renewedCapability?.expiresAt
  };
  return {
    ...body,
    renewalId: input.renewalId ?? id("capability_renewal", body),
    renewalHash: sha256Hex(body)
  };
}

export function verifyCapability(capability, options = {}) {
  if (!capability || typeof capability !== "object") {
    return { valid: false, reason: "Missing capability." };
  }
  if (capability.version !== "mission-bound-capability-v1") {
    return { valid: false, reason: "Unsupported capability version." };
  }

  const {
    capabilityId,
    capabilityHash,
    nullifier,
    ...body
  } = capability;
  const expectedId = id("capability", body);
  if (capabilityId !== expectedId) {
    return { valid: false, reason: "Capability id mismatch." };
  }
  const expectedHash = sha256Hex(body);
  if (capabilityHash !== expectedHash) {
    return { valid: false, reason: "Capability hash mismatch." };
  }
  const expectedNullifier = sha256Hex({
    capabilityId,
    capabilityHash,
    missionIdHash: body.missionIdHash,
    nullifierSeed: body.nullifierSeed,
    settlementReleaseCondition: body.settlementReleaseCondition
  });
  if (nullifier !== expectedNullifier) {
    return { valid: false, reason: "Capability nullifier mismatch." };
  }
  if (!options.allowExpired) {
    const expiry = Date.parse(capability.expiresAt);
    if (Number.isNaN(expiry) || expiry <= Date.now()) {
      return { valid: false, reason: "Capability expired or has invalid expiry." };
    }
  }
  return { valid: true, capabilityHash, capabilityId, nullifier };
}

export function verifyCapabilityRenewal(renewal, previousCapability, renewedCapability, options = {}) {
  if (!renewal || typeof renewal !== "object") {
    return { valid: false, reason: "Missing capability renewal." };
  }
  if (renewal.version !== "mission-bound-capability-renewal-v1") {
    return { valid: false, reason: "Unsupported capability renewal version." };
  }
  const previous = verifyCapability(previousCapability, { allowExpired: true });
  if (!previous.valid) return previous;
  const renewed = verifyCapability(renewedCapability, options);
  if (!renewed.valid) return renewed;

  const { renewalId, renewalHash, ...body } = renewal;
  if (renewalId !== id("capability_renewal", body)) {
    return { valid: false, reason: "Capability renewal id mismatch." };
  }
  if (renewalHash !== sha256Hex(body)) {
    return { valid: false, reason: "Capability renewal hash mismatch." };
  }
  if (renewal.previousCapabilityHash !== previousCapability.capabilityHash) {
    return { valid: false, reason: "Capability renewal previousCapabilityHash mismatch." };
  }
  if (renewal.renewedCapabilityHash !== renewedCapability.capabilityHash) {
    return { valid: false, reason: "Capability renewal renewedCapabilityHash mismatch." };
  }
  for (const key of ["missionIdHash", "holderKeyCommitment", "agentId", "issuer", "audience", "principalHash"]) {
    if (previousCapability[key] !== renewedCapability[key]) {
      return { valid: false, reason: `Capability renewal changed ${key}.` };
    }
  }
  if (renewedCapability.previousCapabilityHash !== previousCapability.capabilityHash) {
    return { valid: false, reason: "Renewed capability does not reference previous capability hash." };
  }
  if (renewedCapability.replacedJti !== previousCapability.jti || renewal.previousJti !== previousCapability.jti) {
    return { valid: false, reason: "Capability renewal previous jti mismatch." };
  }
  if (renewal.renewedJti !== renewedCapability.jti || renewedCapability.jti === previousCapability.jti) {
    return { valid: false, reason: "Capability renewal must use a fresh jti." };
  }
  if (renewedCapability.nullifier === previousCapability.nullifier) {
    return { valid: false, reason: "Capability renewal must use a fresh nullifier." };
  }
  if (!Number.isInteger(renewal.renewalCounter) || renewal.renewalCounter <= Number(previousCapability.renewalCounter ?? 0)) {
    return { valid: false, reason: "Capability renewal counter must increase." };
  }
  if (!isSubset(renewedCapability.allowedDomains ?? [], previousCapability.allowedDomains ?? [])) {
    return { valid: false, reason: "Capability renewal widened allowed domains." };
  }
  if (!isSubset(renewedCapability.allowedActions ?? [], previousCapability.allowedActions ?? [])) {
    return { valid: false, reason: "Capability renewal widened allowed actions." };
  }
  if (!isSubset(renewedCapability.dataScopes ?? [], previousCapability.dataScopes ?? [])) {
    return { valid: false, reason: "Capability renewal widened data scopes." };
  }
  if (!isSubset(renewedCapability.paymentRails ?? [], previousCapability.paymentRails ?? [])) {
    return { valid: false, reason: "Capability renewal widened payment rails." };
  }
  const previousSpend = numericSpend(previousCapability.maxSpendUsd);
  const renewedSpend = numericSpend(renewedCapability.maxSpendUsd);
  if (Number.isNaN(previousSpend) || Number.isNaN(renewedSpend) || renewedSpend > previousSpend) {
    return { valid: false, reason: "Capability renewal widened max spend." };
  }
  return {
    valid: true,
    renewalId,
    renewalHash,
    previousCapabilityHash: previousCapability.capabilityHash,
    renewedCapabilityHash: renewedCapability.capabilityHash
  };
}
