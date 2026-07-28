import fs from "node:fs";
import { buildAgentPassport, proposeMission, approveMission } from "../packages/protocol/missions.js";
import { buildMissionBundle } from "../packages/protocol/protocol-bundles.js";
import { jwks } from "../packages/protocol/authority-keys.js";
import { ZkMissionAuthClient } from "../packages/sdk/client.js";
import { verifyAgentPassport, verifyApproval, verifyMissionBundle } from "../packages/sdk/verify.js";

function schema(path) {
  return JSON.parse(fs.readFileSync(path, "utf8"));
}

function assertType(value, expected, path) {
  if (expected === "integer") {
    if (!Number.isInteger(value)) throw new Error(`${path} must be integer`);
    return;
  }
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

function validateMinimal(value, spec, path = "$") {
  if (spec.type) {
    if (Array.isArray(spec.type)) {
      if (!spec.type.some((type) => (type === "array" ? Array.isArray(value) : type === "null" ? value === null : typeof value === type))) {
        throw new Error(`${path} has invalid type`);
      }
    } else {
      assertType(value, spec.type, path);
    }
  }
  if (spec.const !== undefined && value !== spec.const) {
    throw new Error(`${path} must equal ${spec.const}`);
  }
  for (const key of spec.required ?? []) {
    if (!(key in value)) throw new Error(`${path}.${key} is required`);
  }
  for (const [key, childSpec] of Object.entries(spec.properties ?? {})) {
    if (value[key] === undefined || childSpec.$ref) continue;
    validateMinimal(value[key], childSpec, `${path}.${key}`);
  }
}

function validateArtifacts(artifacts, keySet) {
  validateMinimal(artifacts.agentPassport, schema("schemas/agent-passport.schema.json"));
  validateMinimal(artifacts.mission, schema("schemas/mission.schema.json"));
  validateMinimal(artifacts.approval, schema("schemas/approval.schema.json"));
  validateMinimal(artifacts.checkpointRequest, schema("schemas/checkpoint.schema.json"));
  validateMinimal(artifacts.bundle, schema("schemas/mission-bundle.schema.json"));

  verifyAgentPassport(artifacts.agentPassport, keySet);
  verifyApproval(artifacts.approval, keySet);
  verifyMissionBundle(artifacts.bundle, keySet);
}

function baseMissionInput(agentId) {
  return {
    agentId,
    title: "Conformance mission",
    datasetId: "clinical-failures-q1",
    operation: "risk-summary",
    task: "Summarize private risk for conformance validation.",
    allowedTools: ["private_compute.run", "x402.pay", "x402.settle", "email.send", "zeko.receipt.anchor"],
    allowedScopes: ["compute:clinical", "dataset:clinical-failures-q1"],
    allowedRails: ["zeko", "base"]
  };
}

async function buildRemoteArtifacts(baseUrl) {
  const client = new ZkMissionAuthClient({ baseUrl });
  const discovery = await client.discover();
  const keySet = await client.jwks();
  const { agentPassport } = await client.createAgentPassport({
    agentId: "agent-conformance-remote-001",
    organization: "Conformance Labs",
    domain: "conformance.example"
  });
  const { mission } = await client.proposeMission(baseMissionInput(agentPassport.agentId));
  const { approval } = await client.approveMission({
    missionId: mission.missionId,
    approverId: "policy@example.com",
    issuer: "conformance-idp"
  });
  const checkpointRequest = {
    checkpoint: "before_external_side_effect",
    approval,
    context: {
      agentId: mission.agentId,
      datasetId: mission.datasetId,
      operation: mission.operation,
      action: "email.send"
    }
  };
  const checkpoint = await client.verifyCheckpoint(checkpointRequest);
  if (!checkpoint.ok) throw new Error(`remote checkpoint rejected: ${checkpoint.reason}`);
  const { bundle } = await client.exportBundle({
    agentPassport,
    mission,
    approval,
    auth: { authCommitment: "a".repeat(64), scopeCommitment: "b".repeat(64) },
    receipt: checkpoint.enforcementReceipt,
    zeko: { zkappAddress: "zeko-registry-test-fixture" }
  });
  return { artifacts: { agentPassport, mission, approval, checkpointRequest, bundle }, keySet, discovery, mode: "remote", baseUrl };
}

function buildLocalArtifacts() {
  const artifacts = {};
  artifacts.agentPassport = buildAgentPassport({ agentId: "agent-conformance-001", organization: "Conformance Labs" });
  artifacts.mission = proposeMission(baseMissionInput(artifacts.agentPassport.agentId));
  artifacts.approval = approveMission({
    missionId: artifacts.mission.missionId,
    approverId: "policy@example.com",
    issuer: "conformance-idp"
  });
  artifacts.checkpointRequest = {
    checkpoint: "before_external_side_effect",
    approval: artifacts.approval,
    context: {
      agentId: artifacts.mission.agentId,
      datasetId: artifacts.mission.datasetId,
      operation: artifacts.mission.operation,
      action: "email.send"
    }
  };
  artifacts.bundle = buildMissionBundle({
    agentPassport: artifacts.agentPassport,
    mission: artifacts.mission,
    approval: artifacts.approval,
    auth: { authCommitment: "a".repeat(64), scopeCommitment: "b".repeat(64) },
    zeko: { zkappAddress: "zeko-registry-test-fixture" }
  });
  return { artifacts, keySet: jwks(), discovery: { protocol: "local-primitives" }, mode: "local" };
}

const run = process.env.CONFORMANCE_BASE_URL
  ? await buildRemoteArtifacts(process.env.CONFORMANCE_BASE_URL)
  : buildLocalArtifacts();

validateArtifacts(run.artifacts, run.keySet);

fs.writeFileSync("examples/generated-conformance-artifacts.json", JSON.stringify(run.artifacts, null, 2));

console.log(JSON.stringify({
  ok: true,
  mode: run.mode,
  baseUrl: run.baseUrl ?? null,
  discovery: run.discovery.protocol,
  schemas: 5,
  signatures: ["agentPassport", "approval"],
  bundleIntegrity: "sha256",
  output: "examples/generated-conformance-artifacts.json",
  bundleHash: run.artifacts.bundle.bundleHash
}, null, 2));
