import "reflect-metadata";

import {
  Field,
  Mina,
  Poseidon,
  PrivateKey,
  PublicKey,
  UInt32,
  UInt64,
  fetchAccount
} from "o1js";
import {
  MissionComplianceProgram,
  MissionComplianceProof
} from "../dist-zkapp/MissionComplianceProgram.js";
import {
  MissionEscrow,
  MissionRegistry,
  approvalRegistryKey,
  nullifierRegistryKey,
  receiptRegistryKey,
  revocationRegistryKey
} from "../dist-zkapp/MissionRegistry.js";
import {
  buildZekoRegistryAnchor
} from "../packages/protocol/zeko-chain.js";
import {
  verifyMissionComplianceProofArtifact
} from "../packages/protocol/zeko-proof.js";
import {
  loadRegistryState,
  readStdinJson,
  requireEnv,
  saveRegistryState,
  setRegistryEntry,
  zekoNetwork
} from "./lib/registry-state.mjs";

const input = await readStdinJson();
const artifact = input.proofArtifact;
const escrowInput = input.escrow;
if (!artifact || !escrowInput) {
  throw new Error("proofArtifact and escrow are required.");
}
const network = zekoNetwork();
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
const fee = UInt64.from(process.env.TX_FEE ?? "2000000000");

Mina.setActiveInstance(Mina.Network(network));
const { verificationKey } = await MissionComplianceProgram.compile();
const circuitDigest = await MissionComplianceProgram.digest();
await MissionRegistry.compile();
const proofCheck = await verifyMissionComplianceProofArtifact(artifact, {
  verificationKey,
  circuitDigest,
  proofClass: MissionComplianceProof
});
if (!proofCheck.valid) throw new Error(proofCheck.reason);
const proof = await MissionComplianceProof.fromJSON(artifact.proof);
const statement = proof.publicInput;
const escrow = new MissionEscrow({
  missionIdHash: Field(escrowInput.missionIdHash),
  payer: PublicKey.fromBase58(escrowInput.payer),
  beneficiary: PublicKey.fromBase58(escrowInput.beneficiary),
  amountNanomina: UInt64.from(escrowInput.amountNanomina),
  refundAfterSlot: UInt32.from(escrowInput.refundAfterSlot),
  escrowNonce: Field(escrowInput.escrowNonce)
});
await fetchAccount({ publicKey: registryAddress });
const registry = new MissionRegistry(registryAddress);
const state = loadRegistryState();
registry.registryRoot.get().assertEquals(state.map.getRoot());
registry.sequence.get().assertEquals(
  UInt64.from(state.stored.sequence ?? "0")
);

const approvalKey = approvalRegistryKey(statement.capabilityCommitment);
const revocationKey = revocationRegistryKey(
  statement.capabilityCommitment
);
const nullifierKey = nullifierRegistryKey(statement.nullifier);
const receiptKey = receiptRegistryKey(statement.receiptCommitment);
const witnesses = {
  approval: state.map.getWitness(approvalKey),
  revocation: state.map.getWitness(revocationKey),
  nullifier: state.map.getWitness(nullifierKey)
};
setRegistryEntry(state, nullifierKey, Field(1));
const receiptLeaf = Poseidon.hash([
  statement.receiptCommitment,
  statement.nullifier,
  statement.paymentContextDigest,
  ...statement.beneficiary.toFields(),
  statement.payoutNanomina.value,
  statement.protocolFeeNanomina.value
]);
witnesses.receipt = state.map.getWitness(receiptKey);
setRegistryEntry(state, receiptKey, receiptLeaf);
witnesses.escrow = state.map.getWitness(escrow.key());
setRegistryEntry(state, escrow.key(), escrow.leaf(Field(2)));

const tx = await Mina.transaction(
  { sender: relayerKey.toPublicKey(), fee },
  async () => {
    await registry.settleMission(
      proof,
      escrow,
      witnesses.approval,
      witnesses.revocation,
      witnesses.nullifier,
      witnesses.receipt,
      witnesses.escrow
    );
  }
);
await tx.prove();
const result = await tx.sign([relayerKey]).send();
await result.wait();

const sequence = BigInt(state.stored.sequence ?? "0") + 1n;
const saved = saveRegistryState(state, sequence);
const anchor = buildZekoRegistryAnchor({
  networkId: "zeko:testnet",
  registryAddress: registryAddress.toBase58(),
  transactionHash: result.hash,
  sequence: saved.sequence,
  registryRoot: saved.registryRoot,
  missionIdHash: statement.missionIdHash.toString(),
  capabilityCommitment: statement.capabilityCommitment.toString(),
  approvalCommitment: statement.approvalCommitment.toString(),
  receiptCommitment: statement.receiptCommitment.toString(),
  nullifier: statement.nullifier.toString(),
  paymentContextDigest: statement.paymentContextDigest.toString(),
  beneficiary: statement.beneficiary.toBase58(),
  payoutNanomina: statement.payoutNanomina.toString(),
  protocolFeeNanomina: statement.protocolFeeNanomina.toString(),
  proofArtifactHash: artifact.artifactHash
});
console.log(JSON.stringify({
  ok: true,
  transactionHash: result.hash,
  registryRoot: saved.registryRoot,
  sequence: saved.sequence,
  anchor
}, null, 2));
