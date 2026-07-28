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
  revocationAuthorizationMessage,
  revocationRegistryKey
} from "../dist-zkapp/MissionRegistry.js";
import { canonicalValueToField } from "../packages/protocol/zeko-encoding.js";
import {
  loadRegistryState,
  readStdinJson,
  requireEnv,
  saveRegistryState,
  setRegistryEntry,
  zekoNetwork
} from "./lib/registry-state.mjs";

const input = await readStdinJson();
const rawCommitment =
  input.capabilityCommitment ?? input.capabilityHash;
if (rawCommitment === undefined) {
  throw new Error("capabilityCommitment is required.");
}
const capabilityCommitment = /^[0-9]+$/.test(String(rawCommitment))
  ? Field(rawCommitment)
  : canonicalValueToField(rawCommitment);
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
const network = zekoNetwork();
const fee = UInt64.from(process.env.TX_FEE ?? "2000000000");
Mina.setActiveInstance(Mina.Network(network));
await MissionRegistry.compile();
await fetchAccount({ publicKey: registryAddress });
const registry = new MissionRegistry(registryAddress);
const state = loadRegistryState();
registry.registryRoot.get().assertEquals(state.map.getRoot());
const sequence = UInt64.from(state.stored.sequence ?? "0");
registry.sequence.get().assertEquals(sequence);
const key = revocationRegistryKey(capabilityCommitment);
const witness = state.map.getWitness(key);
const signature = Signature.create(
  authorityKey,
  revocationAuthorizationMessage(
    registryAddress,
    sequence,
    capabilityCommitment
  )
);
const tx = await Mina.transaction(
  { sender: relayerKey.toPublicKey(), fee },
  async () => {
    await registry.revokeCapability(
      capabilityCommitment,
      signature,
      witness
    );
  }
);
await tx.prove();
const result = await tx.sign([relayerKey]).send();
await result.wait();
setRegistryEntry(state, key, Field(1));
const nextSequence = BigInt(state.stored.sequence ?? "0") + 1n;
const saved = saveRegistryState(state, nextSequence);
console.log(JSON.stringify({
  ok: true,
  transactionHash: result.hash,
  capabilityCommitment: capabilityCommitment.toString(),
  registryRoot: saved.registryRoot,
  sequence: saved.sequence,
  registryAddress: registryAddress.toBase58()
}, null, 2));
