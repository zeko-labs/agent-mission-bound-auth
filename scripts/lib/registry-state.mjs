import fs from "node:fs";
import path from "node:path";
import { Field, MerkleMap } from "o1js";

export function registryStatePath() {
  return process.env.MISSION_REGISTRY_STATE_PATH ??
    path.join(process.cwd(), "data", "mission-registry-state.json");
}

export function loadRegistryState() {
  const file = registryStatePath();
  const stored = fs.existsSync(file)
    ? JSON.parse(fs.readFileSync(file, "utf8"))
    : {
        version: "mba-mission-registry-index-v1",
        sequence: "0",
        entries: []
      };
  if (stored.version !== "mba-mission-registry-index-v1") {
    throw new Error("Unsupported local MissionRegistry index version.");
  }
  const map = new MerkleMap();
  for (const [key, value] of stored.entries ?? []) {
    map.set(Field(key), Field(value));
  }
  if (stored.registryRoot && stored.registryRoot !== map.getRoot().toString()) {
    throw new Error("Local MissionRegistry index root is corrupt.");
  }
  return { file, stored, map };
}

export function setRegistryEntry(state, key, value) {
  state.map.set(key, value);
  const entries = new Map(state.stored.entries ?? []);
  entries.set(key.toString(), value.toString());
  state.stored.entries = Array.from(entries.entries()).sort(([a], [b]) =>
    BigInt(a) < BigInt(b) ? -1 : 1
  );
}

export function saveRegistryState(state, sequence) {
  const file = state.file;
  const next = {
    ...state.stored,
    sequence: String(sequence),
    registryRoot: state.map.getRoot().toString(),
    savedAt: new Date().toISOString()
  };
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const temporary = `${file}.${process.pid}.${Date.now()}.tmp`;
  fs.writeFileSync(temporary, `${JSON.stringify(next, null, 2)}\n`, {
    mode: 0o600
  });
  fs.renameSync(temporary, file);
  state.stored = next;
  return next;
}

export async function readStdinJson() {
  let body = "";
  process.stdin.setEncoding("utf8");
  for await (const chunk of process.stdin) body += chunk;
  return body.trim() ? JSON.parse(body) : {};
}

export function requireEnv(name, fallbackName) {
  const value =
    process.env[name] ??
    (fallbackName ? process.env[fallbackName] : undefined);
  if (!value) throw new Error(`${name} is required.`);
  return value;
}

export function zekoNetwork() {
  const mina = process.env.ZEKO_GRAPHQL ?? "https://testnet.zeko.io/graphql";
  const archive =
    process.env.ZEKO_ARCHIVE ??
    "https://archive.testnet.zeko.io/graphql";
  return {
    networkId: "zeko",
    mina: mina.endsWith("/graphql")
      ? mina
      : `${mina.replace(/\/$/, "")}/graphql`,
    archive: archive.endsWith("/graphql")
      ? archive
      : `${archive.replace(/\/$/, "")}/graphql`
  };
}
