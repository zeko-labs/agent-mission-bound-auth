import { id, sha256Hex } from "../protocol/digest.js";
import { verifyJws } from "../protocol/authority-keys.js";
export { verifyHolderProof, verifyTraceChain } from "../protocol/boundary-events.js";
export { verifyExecutionBundle, verifyBrowserMissionProfile, verifyRedactedTraceExport, verifyHandoffReceipt } from "../protocol/browser-profile.js";
export { verifyProductionStrictReceipt, verifyReceipt } from "../protocol/receipts.js";
export { verifyAnchorPayload, verifySettlementState, verifySettlementTransition, verifySettlementTransitionChain } from "../protocol/registry.js";
export { verifyCapability, verifyCapabilityRenewal } from "../protocol/capabilities.js";

function assertJwsMatchesBody(jws, body, jwks, label, typ) {
  const verified = verifyJws(jws, jwks, { typ });
  if (sha256Hex(verified.payload) !== sha256Hex(body)) {
    throw new Error(`${label} JWS payload does not match object body.`);
  }
  return verified;
}

export function verifyAgentPassport(passport, jwks) {
  const {
    passportId,
    passportCommitment,
    authoritySignature: _authoritySignature,
    authorityJws,
    ...body
  } = passport;
  if (!authorityJws) throw new Error("agent passport missing authorityJws");
  if (passportId !== id("agent", body)) throw new Error("agent passport id mismatch");
  if (passportCommitment !== sha256Hex(body)) throw new Error("agent passport commitment mismatch");
  return {
    ok: true,
    ...assertJwsMatchesBody(authorityJws, body, jwks, "agent passport", "agent-passport+jwt")
  };
}

export function verifyApproval(approval, jwks) {
  const {
    approvalId,
    approvalHash,
    authoritySignature: _authoritySignature,
    authorityJws,
    zekoAnchor: _zekoAnchor,
    ...body
  } = approval;
  if (!authorityJws) throw new Error("approval missing authorityJws");
  if (approvalId !== id("approval", body)) throw new Error("approval id mismatch");
  if (approvalHash !== sha256Hex(body)) throw new Error("approval hash mismatch");
  const expiry = Date.parse(approval.expiresAt);
  if (Number.isNaN(expiry) || expiry <= Date.now()) throw new Error("approval expired or has invalid expiry");
  return {
    ok: true,
    ...assertJwsMatchesBody(authorityJws, body, jwks, "approval", "mission-approval+jwt")
  };
}

export function verifyMissionBundle(bundle, jwks) {
  if (bundle.version !== "zk-mission-bundle-v1") {
    throw new Error("unsupported mission bundle version");
  }
  const { bundleHash: _bundleHash, ...body } = bundle;
  const expectedHash = sha256Hex(body);
  if (expectedHash !== bundle.bundleHash) {
    throw new Error("mission bundle hash mismatch");
  }
  if (bundle.agentPassport) verifyAgentPassport(bundle.agentPassport, jwks);
  if (bundle.approval) verifyApproval(bundle.approval, jwks);
  return { ok: true, bundleHash: bundle.bundleHash };
}
