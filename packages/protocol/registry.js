import { id, sha256Hex } from "./digest.js";
import { RECEIPT_SETTLEMENT_STATES, verifyReceipt } from "./receipts.js";

export const SETTLEMENT_LIFECYCLE_TRANSITIONS = Object.freeze({
  receipt_created: ["proof_prepared", "failed", "expired"],
  proof_prepared: ["proof_verified", "failed", "expired"],
  proof_verified: ["anchor_prepared", "failed", "disputed", "expired"],
  anchor_prepared: ["anchored", "failed", "disputed", "expired"],
  anchored: ["settlement_release_allowed", "disputed", "expired"],
  settlement_release_allowed: ["settled", "disputed", "expired"],
  settled: [],
  disputed: ["failed", "settlement_release_allowed"],
  expired: [],
  failed: []
});

export const SETTLEMENT_RELEASE_STATES = new Set([
  "settlement_release_allowed",
  "settled"
]);

export function buildRegistryAnchor(input = {}) {
  const payload = {
    registryVersion: "mba-registry-v1",
    sequence: input.sequence ?? 0,
    missionIdHash: input.missionIdHash,
    capabilityHash: input.capabilityHash,
    statementHash: input.statementHash,
    payloadDigest: input.payloadDigest,
    receiptIdHash: input.receiptIdHash,
    nullifier: input.nullifier,
    previousRoot: input.previousRoot ?? "0",
    networkId: input.networkId ?? "zeko:testnet",
    registryAddress: input.registryAddress ?? null,
    txHash: input.txHash ?? null
  };
  const payloadDigest = input.payloadDigest ?? sha256Hex({
    missionIdHash: payload.missionIdHash,
    capabilityHash: payload.capabilityHash,
    statementHash: payload.statementHash,
    receiptIdHash: payload.receiptIdHash,
    nullifier: payload.nullifier
  });
  const body = {
    ...payload,
    payloadDigest,
    newRoot: input.newRoot ?? sha256Hex({
      previousRoot: payload.previousRoot,
      sequence: payload.sequence,
      payloadDigest,
      nullifier: payload.nullifier
    }),
    proofHash: input.proofHash ?? sha256Hex({
      networkId: payload.networkId,
      registryAddress: payload.registryAddress,
      txHash: payload.txHash,
      payloadDigest
    }),
    anchoredAt: input.anchoredAt ?? new Date().toISOString()
  };
  return {
    ...body,
    anchorId: input.anchorId ?? id("anchor", body)
  };
}

export function buildRegistryAnchorFromReceipt(input = {}) {
  const receipt = input.receipt;
  const receiptCheck = verifyReceipt(receipt, { allowAnchorPrepared: true });
  if (!receiptCheck.valid) {
    throw new Error(receiptCheck.reason);
  }
  const relayerResponse = input.relayerResponse ?? null;
  const proofArtifact = input.proofArtifact ?? null;
  const txHash = input.txHash ?? relayerResponse?.txHash ?? relayerResponse?.transactionHash ?? null;
  const registryAddress = input.registryAddress ?? input.zkappAddress ?? relayerResponse?.registryAddress ?? relayerResponse?.zkappAddress ?? null;
  const networkId = input.networkId ?? relayerResponse?.networkId ?? receipt.anchor?.registry ?? "zeko:testnet";
  const proofHash = input.proofHash ?? sha256Hex({
    proofArtifact,
    relayerResponse,
    registryAddress,
    txHash,
    receiptHash: receipt.receiptHash
  });
  const anchor = buildRegistryAnchor({
    sequence: input.sequence,
    missionIdHash: receipt.mission.missionIdHash,
    capabilityHash: receipt.mission.capabilityHash,
    statementHash: receipt.proof.statementHash,
    receiptIdHash: sha256Hex(receipt.receiptId),
    nullifier: receipt.nullifier,
    previousRoot: input.previousRoot,
    newRoot: input.newRoot,
    networkId,
    registryAddress,
    txHash,
    proofHash,
    anchoredAt: input.anchoredAt
  });
  return {
    anchor,
    verifier: verifyAnchorPayload(receipt, anchor),
    proofArtifactDigest: proofArtifact ? sha256Hex(proofArtifact) : null,
    relayerResponseDigest: relayerResponse ? sha256Hex(relayerResponse) : null
  };
}

export function verifyAnchorPayload(receipt, anchor) {
  const receiptCheck = verifyReceipt(receipt, { allowAnchorPrepared: true });
  if (!receiptCheck.valid) return receiptCheck;
  if (!anchor || typeof anchor !== "object") {
    return { valid: false, reason: "Missing anchor." };
  }
  if (anchor.registryVersion !== "mba-registry-v1") {
    return { valid: false, reason: "Unsupported registry anchor version." };
  }
  const { anchorId, ...body } = anchor;
  if (anchorId !== id("anchor", body)) {
    return { valid: false, reason: "Anchor id mismatch." };
  }
  const expectedPayloadDigest = sha256Hex({
    missionIdHash: anchor.missionIdHash,
    capabilityHash: anchor.capabilityHash,
    statementHash: anchor.statementHash,
    receiptIdHash: anchor.receiptIdHash,
    nullifier: anchor.nullifier
  });
  if (anchor.payloadDigest !== expectedPayloadDigest) {
    return { valid: false, reason: "Anchor payloadDigest mismatch." };
  }
  const expectedRoot = sha256Hex({
    previousRoot: anchor.previousRoot,
    sequence: anchor.sequence,
    payloadDigest: anchor.payloadDigest,
    nullifier: anchor.nullifier
  });
  if (anchor.newRoot !== expectedRoot) {
    return { valid: false, reason: "Anchor newRoot mismatch." };
  }
  if (anchor.missionIdHash !== receipt.mission.missionIdHash) {
    return { valid: false, reason: "Anchor missionIdHash does not match receipt." };
  }
  if (anchor.capabilityHash !== receipt.mission.capabilityHash) {
    return { valid: false, reason: "Anchor capabilityHash does not match receipt." };
  }
  if (anchor.statementHash !== receipt.proof.statementHash) {
    return { valid: false, reason: "Anchor statementHash does not match receipt." };
  }
  if (anchor.receiptIdHash !== sha256Hex(receipt.receiptId)) {
    return { valid: false, reason: "Anchor receiptIdHash does not match receipt." };
  }
  if (anchor.nullifier !== receipt.nullifier) {
    return { valid: false, reason: "Anchor nullifier does not match receipt." };
  }
  if (receipt.anchor && receipt.anchor.payloadDigest !== anchor.payloadDigest) {
    return { valid: false, reason: "Receipt anchor payloadDigest does not match anchor." };
  }
  return {
    valid: true,
    anchorId,
    payloadDigest: anchor.payloadDigest,
    newRoot: anchor.newRoot,
    nullifier: anchor.nullifier
  };
}

export function verifySettlementState(receipt, settlement = {}) {
  const receiptCheck = verifyReceipt(receipt, { allowAnchorPrepared: true });
  if (!receiptCheck.valid) return { valid: false, decision: "release_denied", reason: receiptCheck.reason };
  const safeSettlement = settlement || {};
  const spentNullifiers = new Set(safeSettlement.spentNullifiers ?? safeSettlement.nullifiers ?? []);
  if (spentNullifiers.has(receipt.nullifier)) {
    return { valid: false, decision: "duplicate_payment", reason: "Receipt nullifier already settled." };
  }
  if (safeSettlement.requiredAnchor !== false && !receipt.anchor) {
    return { valid: false, decision: "not_ready", reason: "Receipt anchor evidence is required before settlement." };
  }
  if (!SETTLEMENT_RELEASE_STATES.has(receipt.settlementState)) {
    return { valid: false, decision: "not_ready", reason: "Receipt settlementState does not allow release." };
  }
  if (safeSettlement.allowedRails && !safeSettlement.allowedRails.includes(receipt.payment.rail)) {
    return { valid: false, decision: "policy_violation", reason: "Receipt payment rail is not allowed." };
  }
  if (safeSettlement.expiresAt) {
    const expiry = Date.parse(safeSettlement.expiresAt);
    if (Number.isNaN(expiry) || expiry <= Date.now()) {
      return { valid: false, decision: "expired_authorization", reason: "Settlement authorization expired or has invalid expiry." };
    }
  }
  return {
    valid: true,
    decision: "release_allowed",
    nullifier: receipt.nullifier,
    receiptId: receipt.receiptId
  };
}

export function canTransitionSettlement(from, to) {
  if (!RECEIPT_SETTLEMENT_STATES.has(from) || !RECEIPT_SETTLEMENT_STATES.has(to)) return false;
  return (SETTLEMENT_LIFECYCLE_TRANSITIONS[from] ?? []).includes(to);
}

export function buildSettlementTransition(input = {}) {
  const body = {
    version: "mba-settlement-transition-v1",
    receiptId: input.receiptId,
    receiptHash: input.receiptHash,
    nullifier: input.nullifier,
    from: input.from,
    to: input.to,
    anchorId: input.anchorId ?? null,
    paymentContextDigest: input.paymentContextDigest ?? null,
    reason: input.reason ?? null,
    transitionedAt: input.transitionedAt ?? new Date().toISOString()
  };
  return {
    ...body,
    transitionId: input.transitionId ?? id("settlement_transition", body),
    transitionHash: sha256Hex(body)
  };
}

export function verifySettlementTransition(transition, options = {}) {
  if (!transition || typeof transition !== "object") {
    return { valid: false, reason: "Missing settlement transition." };
  }
  if (transition.version !== "mba-settlement-transition-v1") {
    return { valid: false, reason: "Unsupported settlement transition version." };
  }
  const { transitionId, transitionHash, ...body } = transition;
  if (transitionId !== id("settlement_transition", body)) {
    return { valid: false, reason: "Settlement transition id mismatch." };
  }
  if (transitionHash !== sha256Hex(body)) {
    return { valid: false, reason: "Settlement transition hash mismatch." };
  }
  if (!canTransitionSettlement(transition.from, transition.to)) {
    return { valid: false, reason: `Invalid settlement transition ${transition.from} -> ${transition.to}.` };
  }
  for (const [key, expected] of [
    ["receiptId", options.receiptId],
    ["receiptHash", options.receiptHash],
    ["nullifier", options.nullifier],
    ["paymentContextDigest", options.paymentContextDigest]
  ]) {
    if (expected && transition[key] !== expected) {
      return { valid: false, reason: `Settlement transition ${key} mismatch.` };
    }
  }
  if (SETTLEMENT_RELEASE_STATES.has(transition.to) && options.requireAnchor !== false && !transition.anchorId) {
    return { valid: false, reason: "Settlement release transitions require anchorId." };
  }
  return { valid: true, transitionId, transitionHash };
}

export function verifySettlementTransitionChain(transitions = [], options = {}) {
  if (!Array.isArray(transitions) || transitions.length === 0) {
    return { valid: false, reason: "Settlement transition chain must contain at least one transition." };
  }
  let previousTo = options.initialState ?? transitions[0].from;
  for (const transition of transitions) {
    if (transition.from !== previousTo) {
      return { valid: false, reason: "Settlement transition chain is broken." };
    }
    const check = verifySettlementTransition(transition, options);
    if (!check.valid) return check;
    previousTo = transition.to;
  }
  return {
    valid: true,
    finalState: previousTo,
    transitionCount: transitions.length,
    transitionChainHash: sha256Hex({ transitions: transitions.map((transition) => transition.transitionHash) })
  };
}
