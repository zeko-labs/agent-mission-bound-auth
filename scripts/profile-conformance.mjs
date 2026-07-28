import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { generateKeyPairSync } from "node:crypto";
import {
  buildBrowserMissionProfile,
  buildExecutionBundle,
  buildRedactedTraceExport,
  verifyExecutionBundle
} from "../packages/protocol/browser-profile.js";
import {
  buildBoundaryEvent,
  DIGEST_HOLDER_PROOF_SCHEME,
  ED25519_HOLDER_PROOF_SCHEME,
  verifyBoundaryEvent,
  verifyTraceChain
} from "../packages/protocol/boundary-events.js";
import {
  buildMissionCapability,
  buildMissionPolicy,
  verifyCapability
} from "../packages/protocol/capabilities.js";
import { sha256Hex } from "../packages/protocol/digest.js";
import {
  buildEnterpriseIdentityAttestation
} from "../packages/protocol/identity-attestations.js";
import { buildAgentPassport } from "../packages/protocol/missions.js";
import { enabledRails } from "../packages/protocol/rails.js";
import {
  isDemoMode,
  isProductionProfile,
  isSettlementEnabled,
  isZekoSettlementProfile,
  missionAuthProfile,
  missionSettlementProfile
} from "../packages/protocol/runtime.js";
import {
  buildMockPayment,
  buildPaymentRequirement
} from "../packages/protocol/x402.js";

const previousEnv = { ...process.env };
const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "mba-profiles-"));

function restoreEnvironment() {
  for (const key of Object.keys(process.env)) {
    if (!(key in previousEnv)) delete process.env[key];
  }
  Object.assign(process.env, previousEnv);
}

function configure(profile, settlement, demoMode) {
  process.env.MISSION_AUTH_PROFILE = profile;
  process.env.MISSION_SETTLEMENT_PROFILE = settlement;
  process.env.DEMO_MODE = String(demoMode);
  delete process.env.NODE_ENV;
}

try {
  configure("demo", "none", true);
  assert.equal(missionAuthProfile(), "demo");
  assert.equal(missionSettlementProfile(), "none");
  assert.equal(isDemoMode(), true);
  assert.equal(isProductionProfile(), false);

  const demoPolicy = buildMissionPolicy({
    missionId: "mission-demo",
    task: "Exercise the local implementation path.",
    allowedActions: ["private_compute.run"],
    maxSpendUsd: "1.00",
    expiresAt: new Date(Date.now() + 60_000).toISOString()
  });
  const demoCapability = buildMissionCapability({
    principalHash: sha256Hex("demo-principal"),
    agentId: "demo-agent",
    holderKeyCommitment: sha256Hex("demo-holder"),
    missionId: "mission-demo",
    policyHash: demoPolicy.policyHash,
    allowedActions: demoPolicy.allowedActions,
    maxSpendUsd: demoPolicy.maxSpendUsd,
    expiresAt: demoPolicy.expiresAt
  });
  assert.equal(verifyCapability(demoCapability).valid, true);

  const demoEvent = buildBoundaryEvent({
    missionIdHash: demoCapability.missionIdHash,
    capabilityHash: demoCapability.capabilityHash,
    policyHash: demoPolicy.policyHash,
    action: "private_compute.run",
    holderKeyCommitment: demoCapability.holderKeyCommitment,
    holder: {
      scheme: DIGEST_HOLDER_PROOF_SCHEME,
      holderSecret: "local-holder-proof"
    }
  });
  assert.equal(verifyBoundaryEvent(demoEvent).valid, true);

  const demoRequirement = buildPaymentRequirement({
    jobId: "demo-job",
    datasetId: "demo-dataset",
    operation: "summary"
  });
  const demoPayment = buildMockPayment(
    demoRequirement,
    enabledRails()[0].id
  );
  assert.equal(demoPayment.payload.x402Version, 2);

  configure("portable", "none", false);
  process.env.MISSION_STATE_PATH =
    path.join(stateDir, "portable-missions.json");
  process.env.REVOCATION_STATE_PATH =
    path.join(stateDir, "portable-revocations.json");
  const authorityKeys = generateKeyPairSync("ec", {
    namedCurve: "P-256"
  });
  process.env.MISSION_AUTHORITY_PRIVATE_JWK = JSON.stringify(
    authorityKeys.privateKey.export({ format: "jwk" })
  );

  assert.equal(missionAuthProfile(), "portable");
  assert.equal(missionSettlementProfile(), "none");
  assert.equal(isProductionProfile(), true);
  assert.equal(isSettlementEnabled(), false);
  assert.deepEqual(enabledRails(), []);
  assert.throws(
    () => buildMockPayment(demoRequirement, "zeko"),
    /disabled in production/
  );

  const holderKeys = generateKeyPairSync("ed25519");
  const holderPublicJwk =
    holderKeys.publicKey.export({ format: "jwk" });
  const holderKeyCommitment = sha256Hex(holderPublicJwk);
  const authCommitment = sha256Hex("portable-auth");
  const identityAttestation = buildEnterpriseIdentityAttestation({
    normalizedClaims: {
      provider: "generic-oidc",
      issuer: "https://idp.example/",
      subject: "subject-portable",
      audience: "mba-portable",
      agentId: "portable-agent",
      organization: "Portable Organization",
      scopes: ["browser:act"],
      computeScopes: [],
      datasetScopes: [],
      railScopes: [],
      budget: { maxSpendUsd: "10.00" },
      tokenHash: sha256Hex("portable-token"),
      expiresAt: new Date(Date.now() + 10 * 60_000).toISOString()
    },
    authCommitment,
    scopeCommitment: sha256Hex("portable-scopes")
  });
  const portablePassport = buildAgentPassport({
    identityAttestation,
    holderKeyCommitment,
    domain: "agents.example"
  });
  assert.equal(portablePassport.keyBinding.method, "ed25519-v1");
  assert.equal(
    portablePassport.keyBinding.zekoHolderPublicKey,
    null
  );

  const portablePolicy = buildMissionPolicy({
    missionId: "mission-portable",
    task: "Authorize one browser action without a settlement operator.",
    allowedDomains: ["shop.example"],
    allowedActions: ["cart.prepare"],
    maxSpendUsd: "10.00",
    expiresAt: new Date(Date.now() + 5 * 60_000).toISOString()
  });
  const portableCapability = buildMissionCapability({
    principalHash: sha256Hex("portable-principal"),
    authCommitment,
    identityAttestationHash:
      identityAttestation.attestationHash,
    approvalHash: sha256Hex("portable-approval"),
    agentId: portablePassport.agentId,
    holderKeyCommitment,
    missionId: "mission-portable",
    policyHash: portablePolicy.policyHash,
    allowedDomains: portablePolicy.allowedDomains,
    allowedActions: portablePolicy.allowedActions,
    maxSpendUsd: portablePolicy.maxSpendUsd,
    expiresAt: portablePolicy.expiresAt,
    nullifierCommitment: sha256Hex("portable-nullifier-secret")
  });
  assert.equal(portableCapability.zekoBinding, undefined);
  assert.equal(verifyCapability(portableCapability).valid, true);

  const portableEvent = buildBoundaryEvent({
    missionIdHash: portableCapability.missionIdHash,
    capabilityHash: portableCapability.capabilityHash,
    policyHash: portablePolicy.policyHash,
    action: "cart.prepare",
    targetDomain: "shop.example",
    resource: "cart-123",
    idempotencyKey: "portable-cart-123",
    expiresAt: portablePolicy.expiresAt,
    holderKeyCommitment,
    holder: {
      scheme: ED25519_HOLDER_PROOF_SCHEME,
      privateKey: holderKeys.privateKey
    }
  });
  const portableVerification = {
    verifierMode: "production_strict",
    missionIdHash: portableCapability.missionIdHash,
    capabilityHash: portableCapability.capabilityHash,
    policyHash: portablePolicy.policyHash,
    allowedActions: portablePolicy.allowedActions,
    allowedDomainHashes: [sha256Hex("shop.example")]
  };
  assert.equal(
    verifyBoundaryEvent(portableEvent, portableVerification).valid,
    true
  );
  const portableTrace = verifyTraceChain(
    [portableEvent],
    portableVerification
  );
  assert.equal(portableTrace.valid, true);

  const browserProfile = buildBrowserMissionProfile({
    missionIdHash: portableCapability.missionIdHash,
    capabilityHash: portableCapability.capabilityHash,
    policyHash: portablePolicy.policyHash,
    runtimeId: "extension-runtime-1",
    extensionId: "extension-id",
    holderKeyCommitment,
    sessionId: "session-1",
    tabId: "tab-1",
    currentUrl: "https://shop.example/cart",
    currentDomain: "shop.example",
    pageStateClass: "cart",
    safeNextActionScore: 0.99,
    recommendedAction: "cart.prepare",
    allowedActions: portablePolicy.allowedActions,
    allowedDomains: portablePolicy.allowedDomains
  });
  const redactedTrace = buildRedactedTraceExport({
    missionIdHash: portableCapability.missionIdHash,
    capabilityHash: portableCapability.capabilityHash,
    policyHash: portablePolicy.policyHash,
    events: [portableEvent],
    traceOptions: portableVerification
  });
  const portableBundle = buildExecutionBundle({
    capability: portableCapability,
    policy: portablePolicy,
    browserProfile,
    redactedTrace
  });
  assert.equal(portableBundle.receipt, null);
  assert.equal(portableBundle.zekoAnchor, null);
  assert.equal(
    verifyExecutionBundle(portableBundle, {
      missionIdHash: portableCapability.missionIdHash,
      capabilityHash: portableCapability.capabilityHash,
      policyHash: portablePolicy.policyHash,
      holderKeyCommitment
    }).valid,
    true
  );

  const rejectedDigestEvent = buildBoundaryEvent({
    missionIdHash: portableCapability.missionIdHash,
    capabilityHash: portableCapability.capabilityHash,
    policyHash: portablePolicy.policyHash,
    action: "cart.prepare",
    holderKeyCommitment
  });
  assert.equal(
    verifyBoundaryEvent(rejectedDigestEvent, {
      env: process.env
    }).valid,
    false
  );

  process.env.MISSION_SETTLEMENT_PROFILE = "zeko";
  assert.equal(isZekoSettlementProfile(), true);
  assert.throws(
    () => buildMissionCapability({
      ...portableCapability,
      capabilityId: undefined,
      capabilityHash: undefined,
      nullifier: undefined,
      authorityJws: undefined,
      jti: undefined
    }),
    /valid Zeko binding/
  );
  assert.throws(
    () => buildAgentPassport({
      identityAttestation,
      holderKeyCommitment
    }),
    /zeko_holder_key_binding_required/
  );

  process.env.MISSION_AUTH_PROFILE = "production";
  delete process.env.MISSION_SETTLEMENT_PROFILE;
  assert.equal(
    missionSettlementProfile(),
    "zeko",
    "legacy production profile must preserve Zeko settlement defaults"
  );
  process.env.MISSION_SETTLEMENT_PROFILE = "none";
  assert.equal(missionSettlementProfile(), "none");

  process.env.MISSION_AUTH_PROFILE = "portable";
  process.env.DEMO_MODE = "true";
  assert.throws(
    () => missionAuthProfile(),
    /conflicts with a secure/
  );

  console.log(JSON.stringify({
    ok: true,
    checks: [
      "demo-digest-holder-proof",
      "demo-mock-x402-v2",
      "portable-enterprise-passport",
      "portable-capability-without-zeko",
      "portable-ed25519-browser-event",
      "portable-redacted-execution-bundle",
      "portable-rejects-digest-proof",
      "zeko-requires-proof-binding",
      "legacy-production-settlement-default",
      "profile-conflict-fails-closed"
    ]
  }, null, 2));
} finally {
  restoreEnvironment();
  fs.rmSync(stateDir, { recursive: true, force: true });
}
