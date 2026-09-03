import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { PrivateKey } from "o1js";
import { buildAgentPassport, proposeMission, approveMission, enforceCheckpoint } from "../packages/protocol/missions.js";
import { buildAuthCommitment, normalizeOAuthClaims, verifyJwtWithJwks } from "../packages/protocol/oauth-production.js";
import { verifyPayment } from "../packages/protocol/x402.js";
import { sha256Hex } from "../packages/protocol/digest.js";
import { buildEnterpriseIdentityAttestation } from "../packages/protocol/identity-attestations.js";
import {
  buildMissionCapability,
  renewMissionCapability,
  verifyCapabilityRenewal
} from "../packages/protocol/capabilities.js";
import {
  prepareMissionComplianceBinding,
  zekoHolderKeyCommitment
} from "../packages/protocol/zeko-inputs.js";
import { completeOidcAuthorization } from "../packages/protocol/oidc.js";

function encodeJson(value) {
  return Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
}

function signRsJwt(
  payload,
  privateKey,
  kid = "jwt-test",
  headerOverrides = {}
) {
  const header = {
    typ: "JWT",
    alg: "RS256",
    kid,
    ...headerOverrides
  };
  const signingInput = `${encodeJson(header)}.${encodeJson(payload)}`;
  const signature = cryptoSign("RSA-SHA256", Buffer.from(signingInput), privateKey).toString("base64url");
  return `${signingInput}.${signature}`;
}

function requestJson({ port, path: requestPath, method = "GET", body }) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: "127.0.0.1",
      port,
      path: requestPath,
      method,
      headers: body ? { "content-type": "application/json" } : {}
    }, (res) => {
      let data = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => { data += chunk; });
      res.on("end", () => {
        resolve({
          status: res.statusCode,
          body: data ? JSON.parse(data) : null
        });
      });
    });
    req.on("error", reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

const previousEnv = { ...process.env };
const previousFetch = globalThis.fetch;

try {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "mission-auth-hardening-"));
  process.env.MISSION_AUTH_PROFILE = "production";
  process.env.DEMO_MODE = "false";
  process.env.PUBLIC_BASE_URL = "http://127.0.0.1:0";
  process.env.MISSION_STATE_PATH = path.join(stateDir, "mission-state.json");
  process.env.REVOCATION_STATE_PATH = path.join(stateDir, "revocation-state.json");
  delete process.env.ZK_OAUTH_ISSUER_SECRET;
  assert.throws(
    () => buildAuthCommitment({ scopes: [], subject: "sub" }, "salt"),
    /ZK_OAUTH_ISSUER_SECRET/
  );

  process.env.ZK_OAUTH_ISSUER_SECRET = "production-test-issuer-secret";
  const authorityKeys = generateKeyPairSync("ec", { namedCurve: "P-256" });
  process.env.MISSION_AUTHORITY_PRIVATE_JWK = JSON.stringify(authorityKeys.privateKey.export({ format: "jwk" }));

  const jwtKeys = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const publicJwk = {
    ...jwtKeys.publicKey.export({ format: "jwk" }),
    kid: "jwt-test",
    alg: "RS256",
    use: "sig"
  };
  const now = Math.floor(Date.now() / 1000);
  const jwt = signRsJwt({
    iss: "https://issuer.example/",
    sub: "subject-123",
    aud: "client-123",
    scope: "compute:clinical dataset:clinical-failures-q1 rail:zeko",
    exp: now + 600,
    iat: now,
    nonce: "nonce-123"
  }, jwtKeys.privateKey);
  const claims = await verifyJwtWithJwks(jwt, {
    issuer: "https://issuer.example/",
    audience: "client-123",
    jwks: { keys: [publicJwk] }
  });
  assert.equal(claims.sub, "subject-123");

  const attackerKeys = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const attackerPublicJwk = {
    ...attackerKeys.publicKey.export({ format: "jwk" }),
    kid: "attacker-key",
    alg: "RS256",
    use: "sig"
  };
  const attackerJwt = signRsJwt({
    iss: "https://attacker.example/",
    sub: "attacker-subject",
    aud: "attacker-audience",
    scope: "compute:clinical dataset:clinical-failures-q1 rail:zeko",
    exp: now + 600,
    iat: now
  }, attackerKeys.privateKey, "attacker-key");
  process.env.OIDC_ISSUER = "https://issuer.example/";
  process.env.OIDC_AUDIENCE = "client-123";
  process.env.OIDC_JWKS_URL = "https://issuer.example/jwks.json";
  globalThis.fetch = async (url) => {
    if (String(url) === process.env.OIDC_JWKS_URL) {
      return new Response(JSON.stringify({ keys: [publicJwk] }), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    }
    if (String(url) === "https://attacker.example/jwks.json") {
      return new Response(JSON.stringify({ keys: [attackerPublicJwk] }), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    }
    if (String(url) === "https://issuer.example/token") {
      return Response.json({
        token_type: "Bearer",
        id_token: jwt
      });
    }
    return previousFetch(url);
  };
  const { createServer } = await import("../apps/harness/server.js");
  const server = createServer();
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const { port } = server.address();
    const forgedCommitment = await requestJson({
      port,
      method: "POST",
      path: "/api/oauth/zk-commit",
      body: {
        token: attackerJwt,
        provider: "generic-oidc",
        issuer: "https://attacker.example/",
        audience: "attacker-audience",
        jwksUrl: "https://attacker.example/jwks.json"
      }
    });
    assert.notEqual(forgedCommitment.status, 200);
    assert.match(forgedCommitment.body.message ?? forgedCommitment.body.error, /No JWKS key|internal_error/);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }

  const missingExpJwt = signRsJwt({
    iss: "https://issuer.example/",
    sub: "subject-123",
    aud: "client-123"
  }, jwtKeys.privateKey);
  await assert.rejects(
    () => verifyJwtWithJwks(missingExpJwt, {
      issuer: "https://issuer.example/",
      audience: "client-123",
      jwks: { keys: [publicJwk] }
    }),
    /exp is required/
  );
  await assert.rejects(
    () => verifyJwtWithJwks(jwt, {
      jwks: { keys: [publicJwk] }
    }),
    /pinned issuer and audience/
  );
  const criticalHeaderJwt = signRsJwt({
    iss: "https://issuer.example/",
    sub: "subject-123",
    aud: "client-123",
    exp: now + 600,
    iat: now
  }, jwtKeys.privateKey, "jwt-test", { crit: "b64" });
  await assert.rejects(
    () => verifyJwtWithJwks(criticalHeaderJwt, {
      issuer: "https://issuer.example/",
      audience: "client-123",
      jwks: { keys: [publicJwk] }
    }),
    /critical headers/
  );
  const multiAudienceJwt = signRsJwt({
    iss: "https://issuer.example/",
    sub: "subject-123",
    aud: ["client-123", "another-client"],
    scope: "compute:clinical",
    exp: now + 600,
    iat: now
  }, jwtKeys.privateKey);
  await assert.rejects(
    () => verifyJwtWithJwks(multiAudienceJwt, {
      issuer: "https://issuer.example/",
      audience: "client-123",
      jwks: { keys: [publicJwk] }
    }),
    /azp must match/
  );
  await assert.rejects(
    () => completeOidcAuthorization(
      { code: "stale-code", state: "stale-state" },
      new Map([[
        "stale-state",
        {
          createdAt: Date.now() - (11 * 60 * 1000),
          tokenEndpoint: "https://issuer.example/token"
        }
      ]])
    ),
    /state expired/
  );
  await assert.rejects(
    () => completeOidcAuthorization(
      { code: "resource-code", state: "resource-state" },
      new Map([[
        "resource-state",
        {
          provider: "auth0",
          issuer: "https://issuer.example/",
          audience: "client-123",
          resourceAudience: "private-api",
          clientId: "client-123",
          redirectUri:
            "http://127.0.0.1:8787/api/oauth/callback",
          codeVerifier: "verifier",
          nonce: "nonce-123",
          tokenEndpoint: "https://issuer.example/token",
          jwksUri: process.env.OIDC_JWKS_URL,
          createdAt: Date.now()
        }
      ]])
    ),
    /verifiable JWT access token/
  );

  process.env.AGENT_MAPPINGS_JSON = JSON.stringify([
    {
      subjectKey: "auth0:https://issuer.example/:subject-123",
      agentId: "agent-mapped-123",
      represents: { type: "organization", id: "Mapped Org" }
    }
  ]);
  const normalized = normalizeOAuthClaims({ ...claims, agent_id: "attacker-controlled-agent" }, "auth0");
  assert.equal(normalized.agentId, "agent-mapped-123");
  assert.equal(normalized.subjectKey, "auth0:https://issuer.example/:subject-123");
  assert.throws(
    () => normalizeOAuthClaims({ ...claims, sub: "unmapped-subject" }, "auth0"),
    /No production agent mapping/
  );

  const commitment = buildAuthCommitment(
    normalized,
    "production-hardening-salt",
    process.env.ZK_OAUTH_ISSUER_SECRET
  );
  const identityAttestation = buildEnterpriseIdentityAttestation({
    normalizedClaims: normalized,
    authCommitment: commitment.authCommitment,
    scopeCommitment: commitment.scopeCommitment
  });
  assert.throws(
    () => buildEnterpriseIdentityAttestation({
      normalizedClaims: {
        ...normalized,
        expiresAt: "not-a-date"
      },
      authCommitment: commitment.authCommitment,
      scopeCommitment: commitment.scopeCommitment
    }),
    /expiry must be valid/
  );
  const approverAttestation = buildEnterpriseIdentityAttestation({
    normalizedClaims: {
      ...normalized,
      agentId: "policy-approver-1",
      tokenHash: sha256Hex({
        tokenHash: normalized.tokenHash,
        role: "approver"
      })
    },
    authCommitment: sha256Hex({
      authCommitment: commitment.authCommitment,
      role: "approver"
    }),
    scopeCommitment: commitment.scopeCommitment
  });
  const zekoHolderPrivateKey = PrivateKey.random();
  const zekoHolderPublicKey =
    zekoHolderPrivateKey.toPublicKey().toBase58();
  const zekoHolderCommitment =
    zekoHolderKeyCommitment(zekoHolderPublicKey);
  const holderKeyCommitment = sha256Hex("production-holder-key");
  const passport = buildAgentPassport({
    agentId: normalized.agentId,
    organization: "Mapped Org",
    identityAttestation,
    holderKeyCommitment,
    zekoHolderPublicKey,
    zekoHolderKeyCommitment: zekoHolderCommitment
  });
  const mission = proposeMission({
    agentId: passport.agentId,
    datasetId: "clinical-failures-q1",
    operation: "risk-summary",
    task: "production hardening check",
    allowedDomains: ["compute.example"],
    allowedTools: ["private_compute.run", "x402.settle"],
    allowedScopes: ["compute:clinical", "dataset:clinical-failures-q1"],
    allowedRails: ["zeko"],
    maxSpendUsd: "1.00"
  });
  const approval = approveMission({
    missionId: mission.missionId,
    approverAttestation
  });
  assert.equal(
    approval.zekoHolderKeyCommitment,
    passport.keyBinding.zekoHolderKeyCommitment
  );

  const beneficiary = PrivateKey.random().toPublicKey();
  const domainVerifierPrivateKey = PrivateKey.random();
  process.env.DOMAIN_VERIFIER_PALLAS_PUBLIC_KEYS_JSON =
    JSON.stringify([
      domainVerifierPrivateKey.toPublicKey().toBase58()
    ]);
  const zekoPrepared = await prepareMissionComplianceBinding({
    holderPrivateKey: zekoHolderPrivateKey,
    domainVerifierPublicKey:
      domainVerifierPrivateKey.toPublicKey(),
    beneficiary,
    missionIdHash: sha256Hex(mission.missionId),
    authCommitment: identityAttestation.authCommitment,
    principalHash: sha256Hex(identityAttestation.source),
    agentId: passport.agentId,
    datasetId: mission.datasetId,
    dataScopes: approval.approvedScopes,
    allowedActions: approval.approvedTools,
    allowedDomains: approval.approvedDomains,
    validUntilSlot: 50_000,
    maxSpendUsd: mission.constraints.maxSpendUsd,
    payoutNative: "0.015",
    protocolFeeNative: "0.001"
  });
  const capabilityInput = {
    issuer: "https://mba.example/",
    audience: "mission-verifier",
    principalHash: sha256Hex(identityAttestation.source),
    authCommitment: identityAttestation.authCommitment,
    identityAttestationHash: identityAttestation.attestationHash,
    agentId: passport.agentId,
    holderKeyCommitment,
    missionId: mission.missionId,
    missionIdHash: sha256Hex(mission.missionId),
    approvalHash: approval.approvalHash,
    policyHash: sha256Hex("production-policy"),
    allowedDomains: approval.approvedDomains,
    allowedActions: approval.approvedTools,
    dataScopes: approval.approvedScopes,
    paymentRails: approval.approvedRails,
    maxSpendUsd: mission.constraints.maxSpendUsd,
    expiresAt: approval.expiresAt,
    nullifierCommitment: sha256Hex("production-nullifier-1")
  };
  assert.throws(
    () => buildMissionCapability(capabilityInput),
    /valid Zeko binding/
  );
  const trustedDomainVerifiers =
    process.env.DOMAIN_VERIFIER_PALLAS_PUBLIC_KEYS_JSON;
  process.env.DOMAIN_VERIFIER_PALLAS_PUBLIC_KEYS_JSON = "[]";
  assert.throws(
    () => buildMissionCapability({
      ...capabilityInput,
      zekoBinding: zekoPrepared.binding
    }),
    /not in the production trust set/
  );
  process.env.DOMAIN_VERIFIER_PALLAS_PUBLIC_KEYS_JSON =
    trustedDomainVerifiers;
  const capability = buildMissionCapability({
    ...capabilityInput,
    zekoBinding: zekoPrepared.binding
  });
  assert.equal(
    capability.zekoBinding.holderKeyCommitment,
    passport.keyBinding.zekoHolderKeyCommitment
  );
  assert.throws(
    () => renewMissionCapability(capability, {
      expiresAt: capability.expiresAt,
      nullifierCommitment: sha256Hex("production-nullifier-2")
    }),
    /valid Zeko binding/
  );
  const renewalPrepared = await prepareMissionComplianceBinding({
    holderPrivateKey: zekoHolderPrivateKey,
    domainVerifierPublicKey:
      domainVerifierPrivateKey.toPublicKey(),
    beneficiary,
    missionIdHash: capability.missionIdHash,
    authCommitment: capability.authCommitment,
    principalHash: capability.principalHash,
    agentId: capability.agentId,
    datasetId: mission.datasetId,
    dataScopes: capability.dataScopes,
    allowedActions: capability.allowedActions,
    allowedDomains: capability.allowedDomains,
    validUntilSlot: 50_000,
    maxSpendUsd: capability.maxSpendUsd,
    payoutNative: "0.015",
    protocolFeeNative: "0.001"
  });
  const renewed = renewMissionCapability(capability, {
    expiresAt: capability.expiresAt,
    nullifierCommitment: sha256Hex("production-nullifier-2"),
    zekoBinding: renewalPrepared.binding
  });
  assert.equal(
    verifyCapabilityRenewal(
      renewed.renewal,
      capability,
      renewed.capability
    ).valid,
    true
  );

  const missingExecution = enforceCheckpoint({
    checkpoint: "before_private_compute",
    approval,
    context: {
      agentId: passport.agentId,
      datasetId: mission.datasetId,
      operation: mission.operation,
      action: "private_compute.run",
      railId: "zeko"
    }
  });
  assert.equal(missingExecution.ok, false);
  assert.match(missingExecution.reason, /missionExecutionId/);

  const hmacOnlyApproval = { ...approval };
  delete hmacOnlyApproval.authorityJws;
  const hmacDowngrade = enforceCheckpoint({
    checkpoint: "before_private_compute",
    approval: hmacOnlyApproval,
    context: {
      missionExecutionId: "exec-hmac",
      idempotencyKey: "compute-hmac",
      agentId: passport.agentId,
      datasetId: mission.datasetId,
      operation: mission.operation,
      action: "private_compute.run",
      railId: "zeko"
    }
  });
  assert.equal(hmacDowngrade.ok, false);
  assert.match(
    hmacDowngrade.reason,
    /JWS is required|schema validation/
  );

  const first = enforceCheckpoint({
    checkpoint: "before_private_compute",
    approval,
    context: {
      missionExecutionId: "exec-1",
      idempotencyKey: "compute-1",
      agentId: passport.agentId,
      datasetId: mission.datasetId,
      operation: mission.operation,
      action: "private_compute.run",
      railId: "zeko",
      spendUsd: "0.40"
    }
  });
  assert.equal(first.ok, true);

  const replay = enforceCheckpoint({
    checkpoint: "before_private_compute",
    approval,
    context: {
      missionExecutionId: "exec-1",
      idempotencyKey: "compute-1",
      agentId: passport.agentId,
      datasetId: mission.datasetId,
      operation: mission.operation,
      action: "private_compute.run",
      railId: "zeko",
      spendUsd: "0.40"
    }
  });
  assert.equal(replay.ok, false);
  assert.match(replay.reason, /Replay detected/);

  const budget = enforceCheckpoint({
    checkpoint: "before_private_compute",
    approval,
    context: {
      missionExecutionId: "exec-2",
      idempotencyKey: "compute-2",
      agentId: passport.agentId,
      datasetId: mission.datasetId,
      operation: mission.operation,
      action: "private_compute.run",
      railId: "zeko",
      spendUsd: "0.70"
    }
  });
  assert.equal(budget.ok, false);
  assert.match(budget.reason, /budget exceeded/i);

  const mockPayment = {
    requestId: "req-1",
    railId: "zeko",
    settlementRail: "zeko",
    networkId: "zeko:sepolia",
    amount: "0.1",
    asset: { symbol: "sETH", decimals: 9, standard: "native" },
    payTo: "B62test",
    expiresAtIso: new Date(Date.now() + 60_000).toISOString(),
    authorization: { mode: "mock-facilitator" }
  };
  mockPayment.authorizationDigest = sha256Hex(mockPayment);
  const paymentCheck = verifyPayment({
    extensions: {
      "agent-mission-bound-auth": {
        info: { requestId: "req-1" }
      }
    },
    accepts: [{
      network: "zeko:sepolia",
      amount: "0.1",
      asset: { symbol: "sETH", decimals: 9, standard: "native" },
      payTo: "B62test",
      extra: {
        mba: {
          railId: "zeko",
          settlementRail: "zeko"
        }
      }
    }]
  }, mockPayment);
  assert.equal(paymentCheck.ok, false);
  assert.match(paymentCheck.reason, /verifyAndSettlePayment/);

  console.log(JSON.stringify({ ok: true, checks: ["strict-jwt", "critical-header-rejection", "multi-audience-azp", "stale-oidc-state", "resource-audience-access-token", "provider-pinned-jwks", "agent-mapping", "dual-holder-key-binding", "trusted-domain-verifier", "zeko-capability-binding", "holder-nullifier-renewal", "production-keys", "replay-budget", "online-settlement-required"] }, null, 2));
} finally {
  process.env = previousEnv;
  globalThis.fetch = previousFetch;
}
