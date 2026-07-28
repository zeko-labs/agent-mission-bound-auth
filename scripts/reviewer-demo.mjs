import { spawnSync } from "node:child_process";
import { jwks } from "../packages/protocol/authority-keys.js";

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: process.cwd(),
    encoding: "utf8",
    ...options
  });
  if (result.status !== 0) {
    throw new Error(result.stderr || result.stdout || `${command} failed`);
  }
  return result.stdout.trim();
}

const protocol = JSON.parse(run("npm", ["run", "smoke:protocol", "--silent"], {
  env: { ...process.env }
}));
const conformance = JSON.parse(run("npm", ["run", "test:conformance", "--silent"]));

console.log(JSON.stringify({
  ok: true,
  protocol: "agent-mission-bound-auth",
  proofPoints: {
    discovery: protocol.discovery,
    missionId: protocol.missionId,
    approvalId: protocol.approvalId,
    bundleHash: protocol.bundleHash,
    externalAdapterReceipt: protocol.adapterReceipt,
    offlineJwksKid: jwks().keys[0].kid,
    conformanceBundleHash: conformance.bundleHash,
    zekoImplementation: {
      proofSystem: "zeko-o1js-mission-compliance-v1",
      registry: "MissionRegistry",
      trustlessSmoke: "npm run test:zkapp-trustless"
    }
  },
  checks: [
    "mission approval JWS verified offline",
    "portable bundle hash verified",
    "external app adapter checkpoint verified",
    "x402 payment flow completed",
    "raw private data not released"
  ]
}, null, 2));
