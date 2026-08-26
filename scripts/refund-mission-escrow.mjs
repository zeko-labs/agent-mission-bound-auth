import "reflect-metadata";

import {
  Field,
  Mina,
  PrivateKey,
  PublicKey,
  UInt32,
  UInt64,
  fetchAccount
} from "o1js";
import {
  MissionEscrow,
  MissionRegistry
} from "../dist-zkapp/MissionRegistry.js";
import {
  loadRegistryState,
  readStdinJson,
  requireEnv,
  saveRegistryState,
  setRegistryEntry,
  zekoConfig,
  zekoNetwork
} from "./lib/registry-state.mjs";

const input = await readStdinJson();
const escrowInput = input.escrow ?? input;
const relayerKey = PrivateKey.fromBase58(
  process.env.MISSION_SETTLEMENT_RELAYER_PRIVATE_KEY ??
  requireEnv("DEPLOYER_PRIVATE_KEY")
);
const registryAddress = PublicKey.fromBase58(
  requireEnv(
    "MISSION_REGISTRY_PUBLIC_KEY",
    "PRIVATE_COMPUTE_ZKAPP_PUBLIC_KEY"
  )
);
const escrow = new MissionEscrow({
  missionIdHash: Field(escrowInput.missionIdHash),
  payer: PublicKey.fromBase58(escrowInput.payer),
  beneficiary: PublicKey.fromBase58(escrowInput.beneficiary),
  amountNanomina: UInt64.from(escrowInput.amountNanomina),
  refundAfterSlot: UInt32.from(escrowInput.refundAfterSlot),
  escrowNonce: Field(escrowInput.escrowNonce)
});
const network = zekoNetwork();
const fee = UInt64.from(zekoConfig().transactionFee);
Mina.setActiveInstance(Mina.Network(network));
await MissionRegistry.compile();
await fetchAccount({ publicKey: registryAddress });
const registry = new MissionRegistry(registryAddress);
const state = loadRegistryState();
registry.registryRoot.get().assertEquals(state.map.getRoot());
registry.sequence.get().assertEquals(
  UInt64.from(state.stored.sequence ?? "0")
);
const witness = state.map.getWitness(escrow.key());
const tx = await Mina.transaction(
  { sender: relayerKey.toPublicKey(), fee },
  async () => {
    await registry.refundMission(escrow, witness);
  }
);
await tx.prove();
const result = await tx.sign([relayerKey]).send();
await result.wait();
setRegistryEntry(state, escrow.key(), escrow.leaf(Field(3)));
const nextSequence = BigInt(state.stored.sequence ?? "0") + 1n;
const saved = saveRegistryState(state, nextSequence);
console.log(JSON.stringify({
  ok: true,
  transactionHash: result.hash,
  registryRoot: saved.registryRoot,
  sequence: saved.sequence,
  registryAddress: registryAddress.toBase58()
}, null, 2));
