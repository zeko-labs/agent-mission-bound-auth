import { sha256Hex } from "./digest.js";
import {
  isDemoMode,
  isSettlementEnabled,
  isZekoSettlementProfile,
  missionAuthProfile,
  missionSettlementProfile
} from "./runtime.js";

export function buildDiscoveryDocument(baseUrl) {
  const settlementAdvertised = isDemoMode() || isSettlementEnabled();
  const zekoAdvertised = isDemoMode() || isZekoSettlementProfile();
  return {
    protocol: "zk-mission-auth",
    version: "1.0-draft",
    name: "Agent Mission-Bound Auth",
    description: "Task-bound authorization, approval, payment, and receipt protocol for delegated and autonomous agents.",
    issuer: `${baseUrl}/`,
    profiles: {
      active: {
        auth: missionAuthProfile(),
        settlement: missionSettlementProfile()
      },
      supported: {
        auth: ["demo", "portable", "production"],
        settlement: ["none", "zeko"]
      }
    },
    endpoints: {
      agentPassport: `${baseUrl}/api/agents/passport`,
      proposeMission: `${baseUrl}/api/missions/propose`,
      approveMission: `${baseUrl}/api/missions/approve`,
      issueCapability: `${baseUrl}/api/capabilities/issue`,
      verifyCheckpoint: `${baseUrl}/api/mission/verify-checkpoint`,
      exportBundle: `${baseUrl}/api/mission/export-bundle`,
      oauthProviders: `${baseUrl}/api/oauth/providers`,
      oauthLogin: `${baseUrl}/api/oauth/login`,
      oauthCallback: `${baseUrl}/api/oauth/callback`,
      missionAuthorityJwks: `${baseUrl}/.well-known/mission-authority-jwks.json`,
      ...(settlementAdvertised
        ? { x402Catalog: `${baseUrl}/.well-known/x402.json` }
        : {}),
      ...(zekoAdvertised
        ? { zekoContractPlan: `${baseUrl}/api/zeko/contract-plan` }
        : {})
    },
    capabilities: {
      agentIdentity: ["agent-passport-v1", "enterprise-idp-vouching", "saml-or-oidc-upstream", "oidc-auth-code-pkce"],
      taskScope: ["mission-bound-agent-auth-v1"],
      approvals: ["mission-approval-v1", "portable-mission-snapshot", "offline-jws-verifiable"],
      enforcement: [
        "before_payment_offer",
        "before_private_compute",
        "before_external_side_effect",
        "after_receipt"
      ],
      browserMissions: [
        "mba-browser-mission-profile-v1",
        "mba-redacted-trace-v1",
        "mba-human-handoff-v1",
        "mba-execution-bundle-v1"
      ],
      renewal: ["mission-bound-capability-renewal-v1"],
      verifierModes: ["compatibility", "production", "production_strict"],
      payments: settlementAdvertised
        ? ["x402-v2", "zeko", "ethereum", "base", "arc-preview", "tempo-preview"]
        : [],
      proofSystems: zekoAdvertised
        ? ["zeko-o1js-mission-compliance-v1"]
        : [],
      anchoring: zekoAdvertised
        ? ["zeko:testnet", "mba-zeko-registry-anchor-v1", "MissionRegistry"]
        : [],
      settlementLifecycle: settlementAdvertised
        ? ["receipt_created", "proof_prepared", "proof_verified", "anchor_prepared", "anchored", "settlement_release_allowed", "settled"]
        : []
    }
  };
}

export function buildMissionBundle(input) {
  const bundle = {
    version: "zk-mission-bundle-v1",
    exportedAt: new Date().toISOString(),
    agentPassport: input.agentPassport,
    mission: input.mission,
    approval: input.approval,
    auth: input.auth ?? null,
    payment: input.payment ?? null,
    receipt: input.receipt ?? null,
    zeko: input.zeko ?? null
  };

  return {
    ...bundle,
    bundleHash: sha256Hex(bundle)
  };
}
