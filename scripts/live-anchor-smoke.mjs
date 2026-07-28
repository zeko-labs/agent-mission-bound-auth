import fs from "node:fs";
import { spawn } from "node:child_process";

const proofPath = process.env.MBA_PROOF_ARTIFACT_PATH;
const escrowPath = process.env.MBA_ESCROW_PATH;
if (!proofPath || !escrowPath) {
  throw new Error(
    "MBA_PROOF_ARTIFACT_PATH and MBA_ESCROW_PATH are required for the live settlement smoke."
  );
}
const payload = {
  proofArtifact: JSON.parse(fs.readFileSync(proofPath, "utf8")),
  escrow: JSON.parse(fs.readFileSync(escrowPath, "utf8"))
};
const result = await new Promise((resolve, reject) => {
  const child = spawn(
    process.execPath,
    ["scripts/anchor-private-compute-receipt.mjs"],
    {
      cwd: process.cwd(),
      env: process.env,
      stdio: ["pipe", "pipe", "pipe"]
    }
  );
  let stdout = "";
  let stderr = "";
  child.stdout.on("data", (chunk) => { stdout += chunk; });
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  child.on("close", (code) => {
    if (code === 0) resolve(JSON.parse(stdout));
    else reject(new Error(stderr || stdout || `settlement exited ${code}`));
  });
  child.stdin.end(JSON.stringify(payload));
});
console.log(JSON.stringify(result, null, 2));
