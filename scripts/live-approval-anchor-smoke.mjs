import { spawn } from "node:child_process";
import { createServer } from "../apps/harness/server.js";

function listen(server) {
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      resolve(`http://127.0.0.1:${address.port}`);
    });
  });
}

async function post(base, path, body) {
  const res = await fetch(`${base}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body)
  });
  return { res, body: await res.json() };
}

function runAnchor(payload) {
  return new Promise((resolve, reject) => {
    const child = spawn("node", ["scripts/anchor-mission-approval.mjs"], {
      cwd: process.cwd(),
      env: process.env,
      stdio: ["pipe", "pipe", "pipe"]
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    child.on("close", (code) => {
      if (code !== 0) {
        reject(new Error(stderr || stdout || `anchor exited ${code}`));
        return;
      }
      resolve(JSON.parse(stdout));
    });
    child.stdin.end(JSON.stringify(payload));
  });
}

const server = createServer();
const base = await listen(server);

try {
  const proof = await post(base, "/api/oauth/zk-issue", {});
  const zkOAuthProof = proof.body.zkOAuthProof;
  await post(base, "/api/agents/passport", {
    agentId: zkOAuthProof.revealed.agentId,
    organization: zkOAuthProof.revealed.organization
  });
  const mission = await post(base, "/api/missions/propose", {
    agentId: zkOAuthProof.revealed.agentId,
    datasetId: "clinical-failures-q1",
    operation: "risk-summary",
    task: "Summarize private clinical risk for board memo.",
    title: "Live approval anchor smoke",
    allowedScopes: ["compute:clinical", "dataset:clinical-failures-q1", "x402:pay"],
    allowedRails: ["zeko", "ethereum", "base"]
  });
  const approval = await post(base, "/api/missions/approve", {
    missionId: mission.body.mission.missionId,
    approverId: "live-anchor-approver@example.com",
    issuer: "demo-enterprise-sso"
  });
  const anchor = await runAnchor({
    capabilityCommitment: mission.body.mission.missionHash,
    approvalCommitment: approval.body.approval.approvalHash
  });
  const checkpoint = await post(base, "/api/mission/verify-checkpoint", {
    checkpoint: "before_private_compute",
    approval: {
      ...approval.body.approval,
      zekoAnchor: {
        ...approval.body.approval.zekoAnchor,
        status: "anchored",
        txHash: anchor.transactionHash,
        registryRoot: anchor.registryRoot,
        sequence: anchor.sequence,
        zkappAddress: anchor.registryAddress
      }
    },
    context: {
      agentId: zkOAuthProof.revealed.agentId,
      datasetId: "clinical-failures-q1",
      operation: "risk-summary",
      action: "private_compute.run"
    }
  });
  if (!checkpoint.body.ok) {
    throw new Error(`checkpoint failed: ${JSON.stringify(checkpoint.body)}`);
  }
  console.log(JSON.stringify({
    ok: true,
    missionId: mission.body.mission.missionId,
    approvalId: approval.body.approval.approvalId,
    anchor,
    checkpoint: checkpoint.body.enforcementReceipt
  }, null, 2));
} finally {
  server.close();
}
