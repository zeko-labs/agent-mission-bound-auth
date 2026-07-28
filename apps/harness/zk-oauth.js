import { hmacSha256Hex, id, randomSalt, sha256Hex } from "../../packages/protocol/digest.js";
import { isAuthCommitmentRevoked } from "../../packages/protocol/revocations.js";
import { isProductionProfile, requireConfiguredValue } from "../../packages/protocol/runtime.js";

const ISSUER = "zk-oauth-demo.enterprise.example";

function issuerSecret() {
  return requireConfiguredValue("ZK_OAUTH_ISSUER_SECRET", "local-demo-issuer-secret", "ZK OAuth proof verification");
}

export function issueZkOAuthProof(input = {}) {
  const now = new Date();
  const expiresAt = new Date(now.getTime() + 30 * 60 * 1000);
  const hiddenClaims = {
    agentId: input.agentId ?? "agent-research-ops-001",
    subject: input.subject ?? "oauth|enterprise-user-1842",
    email: input.email ?? "operator@example.com",
    organization: input.organization ?? "Northstar Bio",
    scopes: input.scopes ?? [
      "compute:clinical",
      "dataset:clinical-failures-q1",
      "x402:pay",
      "rail:zeko",
      "rail:base",
      "rail:ethereum",
      "rail:arc",
      "rail:tempo"
    ],
    maxSpendUsd: input.maxSpendUsd ?? "5.00",
    issuedAt: now.toISOString(),
    expiresAt: expiresAt.toISOString()
  };
  const salt = input.salt ?? randomSalt();
  const authCommitment = sha256Hex({ issuer: ISSUER, hiddenClaims, salt });
  const scopeCommitment = sha256Hex({ scopes: hiddenClaims.scopes, salt });
  const revealed = {
    agentId: hiddenClaims.agentId,
    organization: hiddenClaims.organization,
    scopes: hiddenClaims.scopes,
    maxSpendUsd: hiddenClaims.maxSpendUsd,
    expiresAt: hiddenClaims.expiresAt
  };
  const proofBody = {
    version: "zk-oauth-v1",
    issuer: ISSUER,
    authCommitment,
    scopeCommitment,
    revealed
  };

  return {
    ...proofBody,
    proofId: id("zkp", proofBody),
    issuerProofDigest: hmacSha256Hex(issuerSecret(), proofBody)
  };
}

export function verifyZkOAuthProof(proof, requirement) {
  if (!proof || typeof proof !== "object") {
    return { ok: false, reason: "Missing ZK OAuth proof." };
  }
  if (isProductionProfile()) {
    return {
      ok: false,
      reason: "zk-oauth-v1 is a demo artifact and is disabled in production."
    };
  }

  const { proofId, issuerProofDigest, ...proofBody } = proof;
  if (
    proofBody.version !== "zk-oauth-v1" ||
    proofBody.issuer !== ISSUER ||
    proofId !== id("zkp", proofBody)
  ) {
    return { ok: false, reason: "ZK OAuth proof identity is invalid." };
  }
  const expected = hmacSha256Hex(issuerSecret(), proofBody);
  if (issuerProofDigest !== expected) {
    return { ok: false, reason: "ZK OAuth proof digest is invalid." };
  }

  const expiry = Date.parse(proof.revealed?.expiresAt ?? "");
  if (Number.isNaN(expiry) || expiry <= Date.now()) {
    return { ok: false, reason: "ZK OAuth proof is expired or malformed." };
  }

  if (isAuthCommitmentRevoked(proof.authCommitment)) {
    return { ok: false, reason: "ZK OAuth proof has been revoked." };
  }

  const scopes = new Set(proof.revealed?.scopes ?? []);
  for (const scope of requirement.requiredScopes ?? []) {
    if (!scopes.has(scope)) {
      return { ok: false, reason: `Missing required scope: ${scope}` };
    }
  }

  if (requirement.railId && !scopes.has(`rail:${requirement.railId}`)) {
    return { ok: false, reason: `OAuth proof is not authorized for rail:${requirement.railId}.` };
  }

  return {
    ok: true,
    agentId: proof.revealed.agentId,
    organization: proof.revealed.organization,
    authCommitment: proof.authCommitment,
    scopeCommitment: proof.scopeCommitment
  };
}
