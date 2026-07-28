import fs from "node:fs";
import path from "node:path";
import { PrivateKey } from "o1js";

const outputDir = path.join(process.cwd(), "data", "keys");
const outputPath = path.join(outputDir, "mission-registry-zkapp-key.json");

if (fs.existsSync(outputPath) && process.env.FORCE !== "1") {
  const existing = JSON.parse(fs.readFileSync(outputPath, "utf8"));
  console.log(JSON.stringify({
    ok: true,
    reused: true,
    path: outputPath,
    publicKey: existing.publicKey
  }, null, 2));
  process.exit(0);
}

fs.mkdirSync(outputDir, { recursive: true });

const privateKey = PrivateKey.random();
const publicKey = privateKey.toPublicKey().toBase58();
const payload = {
  kind: "mba-mission-registry-zkapp-key-v1",
  publicKey,
  privateKey: privateKey.toBase58(),
  createdAt: new Date().toISOString()
};

fs.writeFileSync(outputPath, JSON.stringify(payload, null, 2), { mode: 0o600 });

console.log(JSON.stringify({
  ok: true,
  reused: false,
  path: outputPath,
  publicKey
}, null, 2));
