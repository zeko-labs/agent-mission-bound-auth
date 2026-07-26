import { generateKeyPairSync } from "node:crypto";
import {
  buildBoundaryEvent,
  buildBrowserMissionProfile,
  buildExecutionBundle,
  buildHandoffReceipt,
  buildMissionCapability,
  buildMissionPolicy,
  buildRedactedTraceExport,
  ED25519_HOLDER_PROOF_SCHEME,
  sha256Hex,
  verifyExecutionBundle,
  verifyTraceChain
} from "../packages/protocol/index.js";

const holder = generateKeyPairSync("ed25519");
const holderPublicJwk = holder.publicKey.export({ format: "jwk" });
const holderKeyCommitment = sha256Hex(holderPublicJwk);
const missionId = "helper-agent-demo";
const missionIdHash = sha256Hex(missionId);
const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();

const policy = buildMissionPolicy({
  missionId,
  task: "Prepare a cart and stop before final approval.",
  allowedDomains: ["shop.example"],
  allowedActions: ["browser.open", "page.read", "cart.prepare", "checkout.review"],
  paymentRails: ["zeko"],
  maxSpendUsd: "20.00",
  expiresAt
});

const capability = buildMissionCapability({
  issuer: "helper-agent-starter",
  audience: "external-app",
  principal: "org:demo",
  agentId: "agent-helper-demo",
  holderPublicKey: holderPublicJwk,
  missionId,
  missionIdHash,
  allowedDomains: policy.allowedDomains,
  allowedActions: policy.allowedActions,
  paymentRails: policy.paymentRails,
  maxSpendUsd: policy.maxSpendUsd,
  expiresAt
});

const profile = buildBrowserMissionProfile({
  missionIdHash,
  capabilityHash: capability.capabilityHash,
  policyHash: policy.policyHash,
  runtimeId: "helper-runtime-demo",
  holderKeyCommitment,
  sessionId: "session-demo",
  tabId: "tab-demo",
  currentUrl: "https://shop.example/cart",
  currentDomain: "shop.example",
  pageStateClass: "cart",
  safeNextActionScore: 0.9,
  recommendedAction: "checkout.review",
  checkoutCheckpoint: "cart",
  allowedDomains: policy.allowedDomains,
  allowedActions: policy.allowedActions
});

const event = buildBoundaryEvent({
  missionIdHash,
  capabilityHash: capability.capabilityHash,
  policyHash: policy.policyHash,
  action: "cart.prepare",
  targetDomain: "shop.example",
  resource: "cart-demo",
  idempotencyKey: "cart-demo-001",
  expiresAt,
  holderKeyCommitment,
  holder: {
    scheme: ED25519_HOLDER_PROOF_SCHEME,
    privateKey: holder.privateKey
  }
});

const trace = verifyTraceChain([event], { verifierMode: "production_strict" });
const redactedTrace = buildRedactedTraceExport({
  missionIdHash,
  capabilityHash: capability.capabilityHash,
  policyHash: policy.policyHash,
  events: [event],
  trace
});
const handoff = buildHandoffReceipt({
  missionIdHash,
  capabilityHash: capability.capabilityHash,
  policyHash: policy.policyHash,
  stopReason: "final_approval_required",
  checkpoint: "final_review",
  action: "checkout.review",
  targetDomain: "shop.example",
  eventHash: event.eventHash,
  traceHash: trace.traceHash,
  paymentContextDigest: event.paymentContextDigest,
  holderKeyThumbprint: holderKeyCommitment
});

const bundle = buildExecutionBundle({
  capability,
  policy,
  browserProfile: profile,
  redactedTrace,
  handoff,
  verifierLinks: ["mba verify bundle execution-bundle.json"]
});

const verified = verifyExecutionBundle(bundle, {
  missionIdHash,
  capabilityHash: capability.capabilityHash,
  policyHash: policy.policyHash,
  holderKeyCommitment
});

console.log(JSON.stringify({
  ok: verified.valid,
  bundleHash: bundle.bundleHash,
  traceHash: trace.traceHash,
  handoff: handoff.stopReason
}, null, 2));
