import { createServer } from "../apps/harness/server.js";

function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      resolve(`http://127.0.0.1:${address.port}`);
    });
  });
}

async function post(base, path, body, headers = {}) {
  const res = await fetch(`${base}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json", ...headers },
    body: JSON.stringify(body)
  });
  return { res, body: await res.json() };
}

async function get(base, path) {
  const res = await fetch(`${base}${path}`);
  return { res, body: await res.json() };
}

async function buildMissionApproval(base, zkOAuthProof, request) {
  await post(base, "/api/agents/passport", {
    agentId: zkOAuthProof.revealed.agentId,
    organization: zkOAuthProof.revealed.organization
  });
  const mission = await post(base, "/api/missions/propose", {
    agentId: zkOAuthProof.revealed.agentId,
    datasetId: request.datasetId,
    operation: request.operation,
    task: request.query,
    title: "Smoke private compute mission",
    allowedDomains: ["example.com"],
    allowedTools: ["private_compute.run", "x402.payment_offer", "x402.pay", "x402.settle", "email.send", "zeko.receipt.anchor"],
    allowedScopes: [
      "compute:clinical",
      "dataset:clinical-failures-q1",
      "x402:pay"
    ],
    allowedRails: ["zeko", "base", "ethereum", "arc", "tempo"]
  });
  const approval = await post(base, "/api/missions/approve", {
    missionId: mission.body.mission.missionId,
    approverId: "smoke-approver@example.com",
    issuer: "smoke-enterprise-sso"
  });
  return approval.body.approval;
}

const server = createServer();
const base = await listen(server);

try {
  const health = await get(base, "/api/health");
  if (!health.body.ok) throw new Error("health check failed");
  const discovery = await get(base, "/.well-known/agent-authorization.json");
  if (discovery.body.protocol !== "zk-mission-auth") throw new Error("agent authorization discovery failed");

  const proof = await post(base, "/api/oauth/zk-issue", {});
  const zkOAuthProof = proof.body.zkOAuthProof;
  if (!zkOAuthProof?.authCommitment) throw new Error("missing zk OAuth proof");

  const productionCommit = await post(base, "/api/oauth/zk-commit", {
    provider: "test-oidc",
    claims: {
      iss: "https://idp.example",
      sub: "agent-subject-1",
      aud: "private-compute",
      azp: "agent-client-1",
      organization: "Northstar Bio",
      scope: "compute:clinical dataset:clinical-failures-q1 rail:zeko budget:small",
      max_spend_usd: "5.00",
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 900
    },
    salt: "smoke-salt"
  });
  if (!productionCommit.body.normalizedClaims?.computeScopes?.includes("compute:clinical")) {
    throw new Error("production claim normalization failed");
  }
  if (!productionCommit.body.authCommitment || !productionCommit.body.scopeCommitment) {
    throw new Error("production auth commitment missing");
  }

  const rails = await get(base, "/api/rails");
  const railIds = rails.body.rails.map((rail) => rail.id);
  const expectedRails = ["zeko", "base", "ethereum", "arc", "tempo"];
  for (const rail of expectedRails) {
    if (!railIds.includes(rail)) throw new Error(`missing rail ${rail}`);
  }

  const request = {
    datasetId: "clinical-failures-q1",
    operation: "risk-summary",
    query: "Find the biggest adverse event or operational risk.",
    zkOAuthProof
  };
  const missionApproval = await buildMissionApproval(base, zkOAuthProof, request);
  request.missionApproval = missionApproval;

  for (const railId of expectedRails) {
    const first = await post(base, "/api/compute", request);
    if (first.res.status !== 402) throw new Error(`expected 402 for ${railId}, got ${first.res.status}`);
    const requirement = first.body.requirement;

    const authorization = await post(base, "/api/payments/mock-authorize", {
      requirement,
      railId,
      payer: zkOAuthProof.revealed.agentId
    });

    const paid = await post(base, "/api/compute", request, {
      "PAYMENT-SIGNATURE": authorization.body.paymentHeader
    });

    if (paid.res.status !== 200) {
      throw new Error(`paid compute failed for ${railId}: ${JSON.stringify(paid.body)}`);
    }
    if (paid.body.rawDataReleased !== false) throw new Error(`raw data leaked for ${railId}`);
    if (!paid.body.receipt?.zekoAuditReceipt?.receiptCommitment) {
      throw new Error(`missing Zeko audit receipt for ${railId}`);
    }
    if (!paid.body.receipt.paymentContextDigest) {
      throw new Error(`missing payment context digest for ${railId}`);
    }
    if (!paid.body.receipt.missionHash || !paid.body.receipt.enforcementReceipts?.length) {
      throw new Error(`missing mission linkage for ${railId}`);
    }
    console.log(`${railId}: ${paid.body.receipt.paymentReceipt.txHash}`);
  }

  const verifyCheckpoint = await post(base, "/api/mission/verify-checkpoint", {
    checkpoint: "before_external_side_effect",
    approval: missionApproval,
    context: {
      agentId: zkOAuthProof.revealed.agentId,
      datasetId: request.datasetId,
      operation: request.operation,
      action: "email.send"
    }
  });
  if (!verifyCheckpoint.body.ok) throw new Error("checkpoint verification endpoint failed");

  const adapter = await post(base, "/api/demo-domain/email/send", {
    agentId: zkOAuthProof.revealed.agentId,
    datasetId: request.datasetId,
    operation: request.operation,
    to: "reviewer@example.com",
    missionApproval
  });
  if (!adapter.body.ok || adapter.body.sent !== false) throw new Error("domain adapter verification failed");

  const bundle = await post(base, "/api/mission/export-bundle", {
    approval: missionApproval,
    auth: {
      authCommitment: zkOAuthProof.authCommitment,
      scopeCommitment: zkOAuthProof.scopeCommitment
    },
    zeko: {
      zkappAddress: "zeko-registry-test-fixture"
    }
  });
  if (!bundle.body.bundle?.bundleHash) throw new Error("mission bundle export failed");

  const revokeProof = await post(base, "/api/oauth/zk-issue", {});
  const revokedProof = revokeProof.body.zkOAuthProof;
  await post(base, "/api/oauth/revoke", {
    authCommitment: revokedProof.authCommitment,
    reason: "smoke-test"
  });
  const rejected = await post(base, "/api/compute", {
    datasetId: "clinical-failures-q1",
    operation: "risk-summary",
    query: "This should be rejected.",
    zkOAuthProof: revokedProof,
    missionApproval
  });
  if (rejected.res.status !== 401 || rejected.body.reason !== "ZK OAuth proof has been revoked.") {
    throw new Error("revoked proof was not rejected");
  }

  console.log("smoke ok");
} finally {
  server.close();
}
