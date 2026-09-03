import "reflect-metadata";

import {
  Field,
  Mina,
  PrivateKey,
  PublicKey,
  Signature,
  UInt64,
  fetchAccount
} from "o1js";
import {
  MissionRegistry,
  approvalAuthorizationMessage,
  approvalRegistryKey
} from "../dist-zkapp/MissionRegistry.js";
import { canonicalValueToField } from "../packages/protocol/zeko-encoding.js";
import {
  loadRegistryState,
  readStdinJson,
  requireEnv,
  saveRegistryState,
  setRegistryEntry,
  zekoConfig,
  zekoNetwork
} from "./lib/registry-state.mjs";
import { compileMissionRegistry } from "./lib/compile-mission-registry.mjs";
import { waitForRegistryState } from "./lib/zeko-confirmation.mjs";

function inputField(value, label) {
  if (value === undefined || value === null) {
    throw new Error(`${label} is required.`);
  }
  return /^[0-9]+$/.test(String(value))
    ? Field(value)
    : canonicalValueToField(value);
}

const input = await readStdinJson();
const network = zekoNetwork();
const relayerKey = PrivateKey.fromBase58(
  requireEnv("DEPLOYER_PRIVATE_KEY")
);
const authorityKey = PrivateKey.fromBase58(
  requireEnv("MISSION_AUTHORITY_ZEKO_PRIVATE_KEY")
);
const registryAddress = PublicKey.fromBase58(
  requireEnv(
    "MISSION_REGISTRY_PUBLIC_KEY",
    "PRIVATE_COMPUTE_ZKAPP_PUBLIC_KEY"
  )
);
const capabilityCommitment = inputField(
  input.capabilityCommitment ?? input.capabilityHash,
  "capabilityCommitment"
);
const approvalCommitment = inputField(
  input.approvalCommitment ?? input.approvalHash,
  "approvalCommitment"
);
const fee = UInt64.from(zekoConfig().transactionFee);

Mina.setActiveInstance(Mina.Network(network));
await compileMissionRegistry();
await fetchAccount({ publicKey: registryAddress });
const registry = new MissionRegistry(registryAddress);
const state = loadRegistryState();
registry.registryRoot.get().assertEquals(state.map.getRoot());
const sequence = UInt64.from(state.stored.sequence ?? "0");
registry.sequence.get().assertEquals(sequence);
const key = approvalRegistryKey(capabilityCommitment);
const witness = state.map.getWitness(key);
const signature = Signature.create(
  authorityKey,
  approvalAuthorizationMessage(
    registryAddress,
    sequence,
    capabilityCommitment,
    approvalCommitment
  )
);
const tx = await Mina.transaction(
  { sender: relayerKey.toPublicKey(), fee },
  async () => {
    await registry.anchorApproval(
      capabilityCommitment,
      approvalCommitment,
      signature,
      witness
    );
  }
);
await tx.prove();
const result = await tx.sign([relayerKey]).send();
setRegistryEntry(state, key, approvalCommitment);
const nextSequence = BigInt(state.stored.sequence ?? "0") + 1n;
await waitForRegistryState(registryAddress, {
  registryRoot: state.map.getRoot().toString(),
  sequence: nextSequence,
  description: "approval anchor"
});
const saved = saveRegistryState(state, nextSequence);
console.log(JSON.stringify({
  ok: true,
  transactionHash: result.hash,
  capabilityCommitment: capabilityCommitment.toString(),
  approvalCommitment: approvalCommitment.toString(),
  registryRoot: saved.registryRoot,
  sequence: saved.sequence,
  registryAddress: registryAddress.toBase58()
}, null, 2));
