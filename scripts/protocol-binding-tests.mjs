import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  buildBoundaryEvent,
  buildMissionCapability,
  buildMissionPolicy,
  buildMissionReceiptExport,
  buildRegistryAnchor,
  sha256Hex,
  verifyAnchorPayload,
  verifyBoundaryEvent,
  verifyCapability,
  verifyReceipt,
  verifySettlementState,
  id,
  ED25519_HOLDER_PROOF_SCHEME,
  verifyTraceChain
} from "../packages/protocol/index.js";

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function recomputeEventEnvelope(event) {
  const { eventId: _eventId, eventHash: _eventHash, ...body } = event;
  return {
    ...body,
    eventId: id("event", body),
    eventHash: sha256Hex(body)
  };
}

function baseArtifacts() {
  const missionId = "mission-binding-001";
  const missionIdHash = sha256Hex(missionId);
  const policy = buildMissionPolicy({
    missionId,
    task: "Run private compute and settle only with a valid receipt",
    allowedDomains: ["compute.example"],
    allowedActions: ["private_compute.run", "x402.settle", "zeko.receipt.anchor"],
    dataScopes: ["dataset:clinical-failures-q1"],
    paymentRails: ["zeko"],
    maxSpendUsd: "1.00",
    expiresAt: new Date(Date.now() + 600_000).toISOString(),
    checkpoints: ["before_private_compute", "after_receipt"]
  });
  const capability = buildMissionCapability({
    issuer: "binding-test",
    audience: "binding-verifier",
    principal: "org:binding-labs",
    agentId: "agent-binding-001",
    holderPublicKey: "holder-binding-pubkey",
    missionId,
    missionIdHash,
    allowedDomains: ["compute.example"],
    allowedActions: policy.allowedActions,
    dataScopes: policy.dataScopes,
    paymentRails: policy.paymentRails,
    maxSpendUsd: "1.00",
    expiresAt: policy.expiresAt,
    nullifierSeed: "binding-nullifier-seed"
  });
  const event = buildBoundaryEvent({
    missionIdHash,
    capabilityHash: capability.capabilityHash,
    policyHash: policy.policyHash,
    action: "private_compute.run",
    targetDomain: "compute.example",
    resource: "clinical-failures-q1",
    paymentContext: { rail: "zeko", amount: "0.40" },
    idempotencyKey: "compute-run-001",
    expiresAt: policy.expiresAt,
    holderKeyCommitment: capability.holderKeyCommitment
  });
  const trace = verifyTraceChain([event], {
    missionIdHash,
    capabilityHash: capability.capabilityHash,
    policyHash: policy.policyHash,
    allowedActions: policy.allowedActions,
    allowedDomainHashes: [sha256Hex("compute.example")]
  });
  assert.equal(trace.valid, true);
  const statementHash = sha256Hex({
    capabilityHash: capability.capabilityHash,
    policyHash: policy.policyHash,
    traceHash: trace.traceHash,
    paymentContextDigest: event.paymentContextDigest
  });
  const receiptInput = {
    missionIdHash,
    capabilityHash: capability.capabilityHash,
    issuer: capability.issuer,
    audience: capability.audience,
    policyHash: policy.policyHash,
    allowedDomainsHash: sha256Hex(policy.allowedDomains),
    allowedActionsHash: sha256Hex(policy.allowedActions),
    maxSpendCommitment: sha256Hex(policy.maxSpendUsd),
    paymentRailsHash: sha256Hex(policy.paymentRails),
    holderKeyThumbprint: capability.holderKeyCommitment,
    trace,
    paymentCommitment: sha256Hex({ rail: "zeko", amount: "0.40" }),
    rail: "zeko",
    amountCommitment: sha256Hex("0.40"),
    paymentContextDigest: event.paymentContextDigest,
    statementHash,
    nullifier: capability.nullifier,
    registryRoot: "0",
    settlementState: "anchor_prepared"
  };
  let receipt = buildMissionReceiptExport(receiptInput);
  const anchor = buildRegistryAnchor({
    sequence: 1,
    missionIdHash,
    capabilityHash: capability.capabilityHash,
    statementHash,
    receiptIdHash: sha256Hex(receipt.receiptId),
    nullifier: capability.nullifier,
    previousRoot: "0",
    networkId: "zeko:sepolia",
    registryAddress: "B62qregistry",
    txHash: `0x${sha256Hex("binding-anchor").slice(0, 64)}`
  });
  receipt = buildMissionReceiptExport({
    ...receiptInput,
    anchor: {
      registry: anchor.networkId,
      payloadDigest: anchor.payloadDigest,
      txHash: anchor.txHash,
      sequence: anchor.sequence,
      nullifier: anchor.nullifier
    },
    settlementState: "settlement_release_allowed"
  });
  return { missionIdHash, policy, capability, event, trace, receipt, anchor };
}

const { missionIdHash, policy, capability, event, receipt, anchor } = baseArtifacts();
const nestedReceiptInjection = clone(receipt);
nestedReceiptInjection.payment.injected = true;
assert.equal(verifyReceipt(nestedReceiptInjection).valid, false);

const differentMission = clone(event);
differentMission.missionIdHash = sha256Hex("mission-binding-002");
assert.equal(verifyBoundaryEvent(differentMission, { missionIdHash }).valid, false);

const differentAction = clone(event);
differentAction.action = "email.send";
differentAction.actionHash = sha256Hex("email.send");
const actionReplay = recomputeEventEnvelope(differentAction);
assert.equal(verifyBoundaryEvent(actionReplay).valid, false);
assert.match(verifyBoundaryEvent(actionReplay).reason, /holder proof/);

const differentDomain = clone(event);
differentDomain.targetDomainHash = sha256Hex("evil.example");
const domainReplay = recomputeEventEnvelope(differentDomain);
assert.equal(verifyBoundaryEvent(domainReplay).valid, false);
assert.match(verifyBoundaryEvent(domainReplay).reason, /holder proof/);

const expiredEvent = buildBoundaryEvent({
  missionIdHash,
  capabilityHash: capability.capabilityHash,
  policyHash: policy.policyHash,
  action: "private_compute.run",
  targetDomain: "compute.example",
  resource: "clinical-failures-q1",
  expiresAt: new Date(Date.now() - 1_000).toISOString(),
  holderKeyCommitment: capability.holderKeyCommitment
});
assert.equal(verifyBoundaryEvent(expiredEvent).valid, false);
assert.match(verifyBoundaryEvent(expiredEvent).reason, /expired/);

const invalidExpiryCapability = {
  ...capability,
  expiresAt: "not-a-date"
};
const invalidExpiryCapabilityBody = (() => {
  const { capabilityId: _capabilityId, capabilityHash: _capabilityHash, nullifier: _nullifier, ...body } = invalidExpiryCapability;
  return body;
})();
invalidExpiryCapability.capabilityHash = sha256Hex(invalidExpiryCapabilityBody);
invalidExpiryCapability.capabilityId = id("capability", invalidExpiryCapabilityBody);
invalidExpiryCapability.nullifier = sha256Hex({
  capabilityId: invalidExpiryCapability.capabilityId,
  capabilityHash: invalidExpiryCapability.capabilityHash,
  missionIdHash: invalidExpiryCapability.missionIdHash,
  nullifierCommitment: invalidExpiryCapability.nullifierCommitment,
  settlementReleaseCondition: invalidExpiryCapability.settlementReleaseCondition
});
assert.equal(verifyCapability(invalidExpiryCapability).valid, false);

const invalidExpiryEvent = buildBoundaryEvent({
  missionIdHash,
  capabilityHash: capability.capabilityHash,
  policyHash: policy.policyHash,
  action: "private_compute.run",
  targetDomain: "compute.example",
  resource: "clinical-failures-q1",
  expiresAt: "not-a-date",
  holderKeyCommitment: capability.holderKeyCommitment
});
assert.equal(verifyBoundaryEvent(invalidExpiryEvent).valid, false);

const ed25519Keys = generateKeyPairSync("ed25519");
const ed25519PublicJwk = ed25519Keys.publicKey.export({ format: "jwk" });
const ed25519Capability = buildMissionCapability({
  issuer: "binding-test",
  audience: "binding-verifier",
  principal: "org:binding-labs",
  agentId: "agent-binding-ed25519",
  holderPublicKey: ed25519PublicJwk,
  missionId: "mission-binding-ed25519",
  allowedDomains: ["compute.example"],
  allowedActions: policy.allowedActions,
  dataScopes: policy.dataScopes,
  paymentRails: policy.paymentRails,
  expiresAt: policy.expiresAt,
  nullifierSeed: "binding-ed25519-nullifier-seed"
});
const ed25519Event = buildBoundaryEvent({
  missionIdHash: ed25519Capability.missionIdHash,
  capabilityHash: ed25519Capability.capabilityHash,
  policyHash: policy.policyHash,
  action: "private_compute.run",
  targetDomain: "compute.example",
  resource: "clinical-failures-q1",
  expiresAt: policy.expiresAt,
  holderKeyCommitment: ed25519Capability.holderKeyCommitment,
  holder: {
    scheme: ED25519_HOLDER_PROOF_SCHEME,
    privateKey: ed25519Keys.privateKey
  }
});
assert.equal(verifyBoundaryEvent(ed25519Event, { requireStrongHolderProof: true }).valid, true);
const extendedExpiryEvent = clone(ed25519Event);
extendedExpiryEvent.expiresAt = new Date(Date.now() + 3_600_000).toISOString();
const extendedExpiryReplay = recomputeEventEnvelope(extendedExpiryEvent);
assert.equal(
  verifyBoundaryEvent(extendedExpiryReplay, {
    requireStrongHolderProof: true
  }).valid,
  false
);
assert.match(
  verifyBoundaryEvent(extendedExpiryReplay, {
    requireStrongHolderProof: true
  }).reason,
  /holder proof/
);
const wrongCurveEvent = clone(ed25519Event);
wrongCurveEvent.holderProof.publicJwk = { ...wrongCurveEvent.holderProof.publicJwk, crv: "X25519" };
wrongCurveEvent.holderProof.keyThumbprint = sha256Hex(wrongCurveEvent.holderProof.publicJwk);
wrongCurveEvent.holderKeyCommitment = wrongCurveEvent.holderProof.keyThumbprint;
const wrongCurveReplay = recomputeEventEnvelope(wrongCurveEvent);
assert.equal(verifyBoundaryEvent(wrongCurveReplay, { requireStrongHolderProof: true }).valid, false);
assert.match(
  verifyBoundaryEvent(wrongCurveReplay, {
    requireStrongHolderProof: true
  }).reason,
  /holder proof|action context/
);
assert.throws(
  () => buildBoundaryEvent({
    missionIdHash,
    capabilityHash: capability.capabilityHash,
    policyHash: policy.policyHash,
    action: "private_compute.run",
    targetDomain: "compute.example",
    resource: "clinical-failures-q1",
    holder: { scheme: "unsupported-holder-proof-v1" }
  }),
  /Unsupported holder proof scheme/
);
assert.equal(verifyTraceChain([ed25519Event], {
  requireStrongHolderProof: true,
  missionIdHash: ed25519Capability.missionIdHash,
  capabilityHash: ed25519Capability.capabilityHash,
  policyHash: policy.policyHash
}).valid, true);

const previousProductionEnv = {
  MISSION_AUTH_PROFILE: process.env.MISSION_AUTH_PROFILE,
  DEMO_MODE: process.env.DEMO_MODE
};
process.env.MISSION_AUTH_PROFILE = "production";
process.env.DEMO_MODE = "false";
assert.equal(verifyBoundaryEvent(event).valid, false);
assert.match(verifyBoundaryEvent(event).reason, /digest-holder-proof/);
assert.equal(verifyBoundaryEvent(ed25519Event).valid, true);
if (previousProductionEnv.MISSION_AUTH_PROFILE === undefined) {
  delete process.env.MISSION_AUTH_PROFILE;
} else {
  process.env.MISSION_AUTH_PROFILE = previousProductionEnv.MISSION_AUTH_PROFILE;
}
if (previousProductionEnv.DEMO_MODE === undefined) {
  delete process.env.DEMO_MODE;
} else {
  process.env.DEMO_MODE = previousProductionEnv.DEMO_MODE;
}

const secondReceipt = clone(receipt);
assert.equal(verifySettlementState(receipt, {
  spentNullifiers: [],
  allowUnverifiedDemoEvidence: true
}).decision, "release_allowed");
assert.equal(verifySettlementState(secondReceipt, { spentNullifiers: [receipt.nullifier] }).decision, "duplicate_payment");
assert.equal(verifySettlementState(receipt, {
  expiresAt: "not-a-date",
  allowUnverifiedDemoEvidence: true
}).decision, "expired_authorization");

const changedPolicy = buildMissionPolicy({
  ...policy,
  allowedDomains: ["compute.example", "new.example"],
  maxSpendUsd: "9.99",
  paymentRails: ["base"]
});
assert.equal(verifyBoundaryEvent(event, { policyHash: changedPolicy.policyHash }).valid, false);

const secondEvent = buildBoundaryEvent({
  missionIdHash,
  capabilityHash: capability.capabilityHash,
  policyHash: policy.policyHash,
  action: "x402.settle",
  targetDomain: "compute.example",
  resource: "clinical-failures-q1",
  previousEventHash: "not-the-first-event",
  expiresAt: policy.expiresAt,
  holderKeyCommitment: capability.holderKeyCommitment
});
assert.equal(verifyTraceChain([event, secondEvent], { missionIdHash }).valid, false);

const mismatchedAnchor = clone(anchor);
mismatchedAnchor.statementHash = sha256Hex("wrong-statement");
assert.equal(verifyAnchorPayload(receipt, mismatchedAnchor).valid, false);

const unanchoredFinalReceipt = buildMissionReceiptExport({
  missionIdHash,
  capabilityHash: capability.capabilityHash,
  issuer: capability.issuer,
  audience: capability.audience,
  policyHash: policy.policyHash,
  allowedDomainsHash: sha256Hex(policy.allowedDomains),
  allowedActionsHash: sha256Hex(policy.allowedActions),
  maxSpendCommitment: sha256Hex(policy.maxSpendUsd),
  paymentRailsHash: sha256Hex(policy.paymentRails),
  holderKeyThumbprint: capability.holderKeyCommitment,
  trace: verifyTraceChain([event], { allowExpired: true }),
  paymentCommitment: receipt.payment.paymentCommitment,
  rail: "zeko",
  amountCommitment: receipt.payment.amountCommitment,
  paymentContextDigest: event.paymentContextDigest,
  statementHash: receipt.proof.statementHash,
  nullifier: capability.nullifier,
  registryRoot: "0",
  anchor: null,
  settlementState: "settled"
});
assert.equal(verifyReceipt(unanchoredFinalReceipt).valid, false);
assert.match(verifyReceipt(unanchoredFinalReceipt).reason, /anchor/);

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "mba-cli-"));
const receiptPath = path.join(tempDir, "receipt.json");
const anchorPath = path.join(tempDir, "anchor.json");
fs.writeFileSync(receiptPath, JSON.stringify(receipt, null, 2));
fs.writeFileSync(anchorPath, JSON.stringify(anchor, null, 2));

const mbaCli = new URL("./mba.mjs", import.meta.url).pathname;
const cliReceipt = JSON.parse(execFileSync(process.execPath, [mbaCli, "verify", "receipt", receiptPath], { encoding: "utf8" }));
assert.equal(cliReceipt.valid, true);
const cliAnchor = JSON.parse(execFileSync(process.execPath, [mbaCli, "verify", "anchor", receiptPath, anchorPath], { encoding: "utf8" }));
assert.equal(cliAnchor.valid, true);
assert.throws(
  () => execFileSync(
    process.execPath,
    [mbaCli, "verify", "settlement", receiptPath, anchorPath],
    { encoding: "utf8" }
  ),
  /status 1|Command failed/
);

console.log(JSON.stringify({
  ok: true,
  checks: [
    "mission-binding",
    "nested-receipt-schema-rejection",
    "action-binding",
    "domain-binding",
    "expiry",
    "duplicate-nullifier",
    "policy-hash",
    "trace-chain",
    "anchor-statement",
    "production-anchor-required",
    "ed25519-holder-proof",
    "holder-proof-expiry-binding",
    "rejects-wrong-ed25519-curve",
    "rejects-unsupported-holder-proof",
    "production-rejects-digest-holder-proof"
  ],
  receiptPath,
  anchorPath
}, null, 2));
