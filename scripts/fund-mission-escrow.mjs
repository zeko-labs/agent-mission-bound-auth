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
const payerKey = PrivateKey.fromBase58(
  process.env.MISSION_ESCROW_PAYER_PRIVATE_KEY ??
  requireEnv("DEPLOYER_PRIVATE_KEY")
);
const registryAddress = PublicKey.fromBase58(
  requireEnv(
    "MISSION_REGISTRY_PUBLIC_KEY",
    "PRIVATE_COMPUTE_ZKAPP_PUBLIC_KEY"
  )
);
const escrow = new MissionEscrow({
  missionIdHash: inputField(input.missionIdHash, "missionIdHash"),
  payer: payerKey.toPublicKey(),
  beneficiary: PublicKey.fromBase58(
    input.beneficiary ?? requireEnv("PRIVATE_COMPUTE_BENEFICIARY_PUBLIC_KEY")
  ),
  amountNanomina: UInt64.from(
    input.amountNativeUnits ?? input.amountNanomina
  ),
  refundAfterSlot: UInt32.from(input.refundAfterSlot),
  escrowNonce: inputField(input.escrowNonce, "escrowNonce")
});
const fee = UInt64.from(zekoConfig().transactionFee);

Mina.setActiveInstance(Mina.Network(network));
await compileMissionRegistry();
await fetchAccount({ publicKey: registryAddress });
const registry = new MissionRegistry(registryAddress);
const state = loadRegistryState();
registry.registryRoot.get().assertEquals(state.map.getRoot());
registry.sequence.get().assertEquals(
  UInt64.from(state.stored.sequence ?? "0")
);
const witness = state.map.getWitness(escrow.key());
const tx = await Mina.transaction(
  { sender: payerKey.toPublicKey(), fee },
  async () => {
    await registry.fundMission(escrow, witness);
  }
);
await tx.prove();
const result = await tx.sign([payerKey]).send();
setRegistryEntry(state, escrow.key(), escrow.leaf());
const nextSequence = BigInt(state.stored.sequence ?? "0") + 1n;
await waitForRegistryState(registryAddress, {
  registryRoot: state.map.getRoot().toString(),
  sequence: nextSequence,
  description: "mission escrow funding"
});
const saved = saveRegistryState(state, nextSequence);
console.log(JSON.stringify({
  ok: true,
  transactionHash: result.hash,
  registryAddress: registryAddress.toBase58(),
  registryRoot: saved.registryRoot,
  escrow: {
    missionIdHash: escrow.missionIdHash.toString(),
    payer: escrow.payer.toBase58(),
    beneficiary: escrow.beneficiary.toBase58(),
    amountNativeUnits: escrow.amountNanomina.toString(),
    refundAfterSlot: escrow.refundAfterSlot.toString(),
    escrowNonce: escrow.escrowNonce.toString(),
    escrowKey: escrow.key().toString()
  },
  sequence: saved.sequence
}, null, 2));
