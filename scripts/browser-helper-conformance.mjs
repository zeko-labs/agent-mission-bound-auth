import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  buildBoundaryEvent,
  buildBrowserMissionProfile,
  buildExecutionBundle,
  buildHandoffReceipt,
  buildMissionCapability,
  buildMissionPolicy,
  buildMissionReceiptExport,
  buildRedactedTraceExport,
  buildRegistryAnchorFromReceipt,
  buildSettlementTransition,
  BROWSER_HELPER_ED25519_COMPAT_HOLDER_PROOF_SCHEME,
  ED25519_HOLDER_PROOF_SCHEME,
  renewMissionCapability,
  id,
  sha256Hex,
  verifyBoundaryEvent,
  verifyBrowserMissionProfile,
  verifyCapabilityRenewal,
  verifyExecutionBundle,
  verifyHandoffReceipt,
  verifyProductionStrictReceipt,
  verifyRedactedTraceExport,
  verifySettlementState,
  verifySettlementTransitionChain,
  verifyTraceChain
} from "../packages/protocol/index.js";

function recomputeEventEnvelope(event) {
  const { eventId: _eventId, eventHash: _eventHash, ...body } = event;
  return {
    ...body,
    eventId: id("event", body),
    eventHash: sha256Hex(body)
  };
}

function schema(name) {
  return JSON.parse(fs.readFileSync(new URL(`../schemas/${name}.schema.json`, import.meta.url), "utf8"));
}

function assertType(value, expected, path) {
  if (expected === "array") {
    if (!Array.isArray(value)) throw new Error(`${path} must be array`);
    return;
  }
  if (expected === "null") {
    if (value !== null) throw new Error(`${path} must be null`);
    return;
  }
  if (typeof value !== expected) throw new Error(`${path} must be ${expected}`);
}

function validateMinimal(value, spec, pathName = "$") {
  if (spec.type) {
    if (Array.isArray(spec.type)) {
      if (!spec.type.some((type) => (type === "array" ? Array.isArray(value) : type === "null" ? value === null : typeof value === type))) {
        throw new Error(`${pathName} has invalid type`);
      }
    } else {
      assertType(value, spec.type, pathName);
    }
  }
  if (spec.const !== undefined && value !== spec.const) {
    throw new Error(`${pathName} must equal ${spec.const}`);
  }
  for (const key of spec.required ?? []) {
    if (!(key in value)) throw new Error(`${pathName}.${key} is required`);
  }
  for (const [key, childSpec] of Object.entries(spec.properties ?? {})) {
    if (value[key] === undefined || childSpec.$ref) continue;
    validateMinimal(value[key], childSpec, `${pathName}.${key}`);
  }
}

async function remoteSmoke(baseUrl) {
  const discovery = await fetch(new URL("/.well-known/agent-authorization.json", baseUrl));
  assert.equal(discovery.ok, true, "remote discovery should respond");
  const discoveryJson = await discovery.json();
  assert.equal(discoveryJson.protocol, "zk-mission-auth");

  const jwks = await fetch(new URL("/.well-known/mission-authority-jwks.json", baseUrl));
  assert.equal(jwks.ok, true, "remote JWKS should respond");
  const jwksJson = await jwks.json();
  assert.equal(Array.isArray(jwksJson.keys), true);
  return { discovery: discoveryJson.protocol, jwksKeys: jwksJson.keys.length };
}

function signCompatProof({ event, privateKey, publicJwk, appChallengeHash }) {
  return {
    scheme: BROWSER_HELPER_ED25519_COMPAT_HOLDER_PROOF_SCHEME,
    keyThumbprint: sha256Hex(publicJwk),
    publicJwk,
    messageHash: event.holderProof.messageHash,
    appChallengeHash,
    signature: cryptoSign(null, Buffer.from(appChallengeHash, "utf8"), privateKey).toString("base64url")
  };
}

const missionId = "browser-helper-mission-001";
const missionIdHash = sha256Hex(missionId);
const keys = generateKeyPairSync("ed25519");
const publicJwk = keys.publicKey.export({ format: "jwk" });
const holderKeyCommitment = sha256Hex(publicJwk);
const expiresAt = new Date(Date.now() + 600_000).toISOString();

const policy = buildMissionPolicy({
  missionId,
  task: "Buy one approved office supply item without submitting final payment.",
  allowedDomains: ["shop.example"],
  allowedActions: [
    "browser.open",
    "page.read",
    "cart.prepare",
    "shipping.prepare",
    "payment.prepare",
    "checkout.review"
  ],
  paymentRails: ["zeko"],
  maxSpendUsd: "25.00",
  expiresAt,
  checkpoints: ["cart", "shipping", "payment_selection", "final_review"]
});

const capability = buildMissionCapability({
  issuer: "browser-helper-conformance",
  audience: "browser-helper",
  principal: "org:example",
  agentId: "agent-browser-helper-001",
  runtimeId: "browser-helper-001",
  holderPublicKey: publicJwk,
  missionId,
  missionIdHash,
  allowedDomains: policy.allowedDomains,
  allowedActions: policy.allowedActions,
  paymentRails: policy.paymentRails,
  maxSpendUsd: policy.maxSpendUsd,
  expiresAt,
  nullifierSeed: "browser-helper-nullifier-seed"
});

const { capability: renewedCapability, renewal } = renewMissionCapability(capability, {
  allowedActions: ["browser.open", "page.read", "cart.prepare", "checkout.review"],
  maxSpendUsd: "20.00",
  expiresAt: new Date(Date.now() + 900_000).toISOString(),
  renewalReason: "mission_capability_expired"
});
assert.equal(verifyCapabilityRenewal(renewal, capability, renewedCapability).valid, true);
validateMinimal(renewal, schema("capability-renewal"));

const profile = buildBrowserMissionProfile({
  missionIdHash,
  capabilityHash: renewedCapability.capabilityHash,
  policyHash: policy.policyHash,
  runnerType: "extension-helper",
  runtimeId: "browser-helper-001",
  extensionId: "browser-helper-local-extension",
  holderKeyCommitment,
  sessionId: "session-123",
  tabId: "tab-abc",
  currentUrl: "https://shop.example/cart",
  currentDomain: "shop.example",
  pageStateClass: "cart",
  safeNextActionScore: 0.92,
  recommendedAction: "checkout.review",
  checkoutCheckpoint: "cart",
  allowedActions: policy.allowedActions,
  allowedDomains: policy.allowedDomains,
  requiredCheckpoints: policy.checkpoints
});
assert.equal(verifyBrowserMissionProfile(profile, {
  missionIdHash,
  capabilityHash: renewedCapability.capabilityHash,
  policyHash: policy.policyHash,
  holderKeyCommitment,
  requireDomainHash: true,
  requireTabCommitment: true
}).valid, true);
validateMinimal(profile, schema("browser-profile"));

const cartEvent = buildBoundaryEvent({
  missionIdHash,
  capabilityHash: renewedCapability.capabilityHash,
  policyHash: policy.policyHash,
  action: "cart.prepare",
  targetDomain: "shop.example",
  resource: { cartId: "cart-123", itemCommitment: sha256Hex("approved-office-supply") },
  paymentContext: { rail: "zeko", amount: "19.99" },
  idempotencyKey: "cart-prepare-001",
  expiresAt,
  holderKeyCommitment,
  holder: {
    scheme: ED25519_HOLDER_PROOF_SCHEME,
    privateKey: keys.privateKey
  }
});
assert.equal(verifyBoundaryEvent(cartEvent, {
  verifierMode: "production_strict",
  missionIdHash,
  capabilityHash: renewedCapability.capabilityHash,
  policyHash: policy.policyHash,
  allowedActions: policy.allowedActions,
  allowedDomainHashes: [sha256Hex("shop.example")]
}).valid, true);

const compatEvent = buildBoundaryEvent({
  missionIdHash,
  capabilityHash: renewedCapability.capabilityHash,
  policyHash: policy.policyHash,
  action: "page.read",
  targetDomain: "shop.example",
  resource: "cart-summary",
  idempotencyKey: "page-read-compat-001",
  expiresAt,
  holderKeyCommitment,
  holder: {
    scheme: ED25519_HOLDER_PROOF_SCHEME,
    privateKey: keys.privateKey
  }
});
compatEvent.holderProof = signCompatProof({
  event: compatEvent,
  privateKey: keys.privateKey,
  publicJwk,
  appChallengeHash: sha256Hex({ app: "browser-helper", challenge: "browser-proof-of-possession" })
});
const compatEventEnvelope = recomputeEventEnvelope(compatEvent);
const compatAccepted = verifyBoundaryEvent(compatEventEnvelope, { verifierMode: "compatibility" });
assert.equal(compatAccepted.valid, true);
assert.equal(verifyBoundaryEvent(compatEventEnvelope, { verifierMode: "production_strict" }).valid, false);

const trace = verifyTraceChain([cartEvent], {
  verifierMode: "production_strict",
  missionIdHash,
  capabilityHash: renewedCapability.capabilityHash,
  policyHash: policy.policyHash,
  allowedActions: policy.allowedActions,
  allowedDomainHashes: [sha256Hex("shop.example")]
});
assert.equal(trace.valid, true);

const redactedTrace = buildRedactedTraceExport({
  missionIdHash,
  capabilityHash: renewedCapability.capabilityHash,
  policyHash: policy.policyHash,
  events: [cartEvent],
  traceOptions: { verifierMode: "production_strict" },
  ownerTrace: {
    rawUrl: "https://shop.example/cart",
    selector: "#checkout",
    typedText: "private owner-only trace"
  }
});
assert.equal(verifyRedactedTraceExport(redactedTrace, {
  missionIdHash,
  capabilityHash: renewedCapability.capabilityHash,
  policyHash: policy.policyHash
}).valid, true);
validateMinimal(redactedTrace, schema("redacted-trace"));
const leakingTrace = JSON.parse(JSON.stringify(redactedTrace));
leakingTrace.publicEvents[0].selector = "#checkout";
const { redactedTraceId: _id, redactedTraceHash: _hash, ...leakingBody } = leakingTrace;
leakingTrace.redactedTraceId = `redacted_trace_${sha256Hex(leakingBody).slice(0, 24)}`;
leakingTrace.redactedTraceHash = sha256Hex(leakingBody);
assert.equal(verifyRedactedTraceExport(leakingTrace).valid, false);

const handoff = buildHandoffReceipt({
  missionIdHash,
  capabilityHash: renewedCapability.capabilityHash,
  policyHash: policy.policyHash,
  stopReason: "final_approval_required",
  checkpoint: "final_review",
  action: "checkout.review",
  targetDomain: "shop.example",
  eventHash: cartEvent.eventHash,
  traceHash: trace.traceHash,
  paymentContextDigest: cartEvent.paymentContextDigest,
  holderKeyThumbprint: holderKeyCommitment
});
assert.equal(verifyHandoffReceipt(handoff, {
  missionIdHash,
  capabilityHash: renewedCapability.capabilityHash,
  policyHash: policy.policyHash
}).valid, true);
validateMinimal(handoff, schema("handoff-receipt"));

const statementHash = sha256Hex({
  capabilityHash: renewedCapability.capabilityHash,
  policyHash: policy.policyHash,
  traceHash: trace.traceHash,
  paymentContextDigest: cartEvent.paymentContextDigest,
  stopReason: handoff.stopReason
});
const receiptInput = {
  missionIdHash,
  capabilityHash: renewedCapability.capabilityHash,
  issuer: renewedCapability.issuer,
  audience: renewedCapability.audience,
  policyHash: policy.policyHash,
  allowedDomainsHash: sha256Hex(policy.allowedDomains),
  allowedActionsHash: sha256Hex(policy.allowedActions),
  maxSpendCommitment: sha256Hex(policy.maxSpendUsd),
  paymentRailsHash: sha256Hex(policy.paymentRails),
  holderKeyThumbprint: holderKeyCommitment,
  proofScheme: ED25519_HOLDER_PROOF_SCHEME,
  trace,
  paymentCommitment: sha256Hex({ rail: "zeko", amount: "19.99" }),
  rail: "zeko",
  amountCommitment: sha256Hex("19.99"),
  paymentContextDigest: cartEvent.paymentContextDigest,
  statementHash,
  nullifier: renewedCapability.nullifier,
  registryRoot: "0",
  settlementState: "anchored"
};
const preAnchorReceipt = buildMissionReceiptExport(receiptInput);
const anchorResult = buildRegistryAnchorFromReceipt({
  receipt: preAnchorReceipt,
  proofArtifact: { proofSystem: "signed-commitment-transition", statementHash },
  relayerResponse: {
    networkId: "zeko:testnet",
    zkappAddress: "B62qbrowserhelperregistry",
    txHash: `0x${sha256Hex("browser-helper-anchor").slice(0, 64)}`
  },
  sequence: 7,
  previousRoot: "0"
});
assert.equal(anchorResult.verifier.valid, true);

const anchoredReceipt = buildMissionReceiptExport({
  ...receiptInput,
  anchor: {
    registry: anchorResult.anchor.networkId,
    payloadDigest: anchorResult.anchor.payloadDigest,
    txHash: anchorResult.anchor.txHash,
    sequence: anchorResult.anchor.sequence,
    nullifier: anchorResult.anchor.nullifier
  },
  settlementState: "settlement_release_allowed"
});
assert.equal(verifyProductionStrictReceipt(anchoredReceipt).valid, true);
assert.equal(verifySettlementState(anchoredReceipt, {
  allowedRails: ["zeko"],
  spentNullifiers: []
}).decision, "release_allowed");

const transitions = [
  buildSettlementTransition({
    receiptId: anchoredReceipt.receiptId,
    receiptHash: anchoredReceipt.receiptHash,
    nullifier: anchoredReceipt.nullifier,
    from: "receipt_created",
    to: "proof_prepared",
    paymentContextDigest: anchoredReceipt.payment.paymentContextDigest
  }),
  buildSettlementTransition({
    receiptId: anchoredReceipt.receiptId,
    receiptHash: anchoredReceipt.receiptHash,
    nullifier: anchoredReceipt.nullifier,
    from: "proof_prepared",
    to: "proof_verified",
    paymentContextDigest: anchoredReceipt.payment.paymentContextDigest
  }),
  buildSettlementTransition({
    receiptId: anchoredReceipt.receiptId,
    receiptHash: anchoredReceipt.receiptHash,
    nullifier: anchoredReceipt.nullifier,
    from: "proof_verified",
    to: "anchor_prepared",
    paymentContextDigest: anchoredReceipt.payment.paymentContextDigest
  }),
  buildSettlementTransition({
    receiptId: anchoredReceipt.receiptId,
    receiptHash: anchoredReceipt.receiptHash,
    nullifier: anchoredReceipt.nullifier,
    from: "anchor_prepared",
    to: "anchored",
    anchorId: anchorResult.anchor.anchorId,
    paymentContextDigest: anchoredReceipt.payment.paymentContextDigest
  }),
  buildSettlementTransition({
    receiptId: anchoredReceipt.receiptId,
    receiptHash: anchoredReceipt.receiptHash,
    nullifier: anchoredReceipt.nullifier,
    from: "anchored",
    to: "settlement_release_allowed",
    anchorId: anchorResult.anchor.anchorId,
    paymentContextDigest: anchoredReceipt.payment.paymentContextDigest
  })
];
assert.equal(verifySettlementTransitionChain(transitions, {
  receiptId: anchoredReceipt.receiptId,
  nullifier: anchoredReceipt.nullifier,
  paymentContextDigest: anchoredReceipt.payment.paymentContextDigest
}).valid, true);

const bundle = buildExecutionBundle({
  capability: renewedCapability,
  policy,
  browserProfile: profile,
  redactedTrace,
  handoff,
  receipt: anchoredReceipt,
  zekoAnchor: anchorResult.anchor,
  settlement: {
    state: "settlement_release_allowed",
    decision: "release_allowed",
    transitionChainHash: verifySettlementTransitionChain(transitions).transitionChainHash
  },
  verifierLinks: ["mba verify bundle execution-bundle.json"],
  ownerTraceUrl: "https://owner.example/private-trace/123"
});
assert.equal(verifyExecutionBundle(bundle, {
  missionIdHash,
  capabilityHash: renewedCapability.capabilityHash,
  policyHash: policy.policyHash,
  holderKeyCommitment
}).valid, true);
validateMinimal(bundle, schema("execution-bundle"));

const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "mba-browser-helper-"));
const bundlePath = path.join(tempDir, "execution-bundle.json");
fs.writeFileSync(bundlePath, JSON.stringify(bundle, null, 2));
const mbaCli = new URL("./mba.mjs", import.meta.url).pathname;
const cliBundle = JSON.parse(execFileSync(process.execPath, [mbaCli, "verify", "bundle", bundlePath], { encoding: "utf8" }));
assert.equal(cliBundle.valid, true);

const remote = process.env.BROWSER_HELPER_CONFORMANCE_BASE_URL
  ? await remoteSmoke(process.env.BROWSER_HELPER_CONFORMANCE_BASE_URL)
  : null;

console.log(JSON.stringify({
  ok: true,
  mode: remote ? "remote-plus-local" : "local",
  remote,
  checks: [
    "browser-profile",
    "capability-renewal",
    "production-strict-holder-proof",
    "compatibility-holder-proof-rejected-in-strict",
    "redacted-trace",
    "new-schema-validation",
    "handoff-receipt",
    "registry-anchor-helper",
    "settlement-lifecycle",
    "execution-bundle",
    "cli-bundle-verifier"
  ],
  bundlePath
}, null, 2));
