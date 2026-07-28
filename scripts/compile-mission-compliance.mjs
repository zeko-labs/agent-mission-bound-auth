import fs from "node:fs";
import path from "node:path";
import { MissionComplianceProgram } from "../dist-zkapp/MissionComplianceProgram.js";

const { verificationKey } = await MissionComplianceProgram.compile();
const circuitDigest = await MissionComplianceProgram.digest();
const artifact = {
  version: "mba-mission-compliance-verification-key-v1",
  circuitDigest,
  verificationKey: {
    data: verificationKey.data,
    hash: verificationKey.hash.toString()
  },
  compiledAt: new Date().toISOString()
};
const outIndex = process.argv.indexOf("--out");
if (outIndex >= 0) {
  const output = path.resolve(process.argv[outIndex + 1]);
  fs.mkdirSync(path.dirname(output), { recursive: true });
  fs.writeFileSync(output, `${JSON.stringify(artifact, null, 2)}\n`);
  console.log(JSON.stringify({
    ok: true,
    output,
    circuitDigest,
    verificationKeyHash: artifact.verificationKey.hash
  }, null, 2));
} else {
  console.log(JSON.stringify(artifact, null, 2));
}
