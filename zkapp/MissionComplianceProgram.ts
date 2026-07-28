import {
  Bool,
  Field,
  MerkleMapWitness,
  Poseidon,
  Provable,
  PublicKey,
  Signature,
  Struct,
  UInt32,
  UInt64,
  ZkProgram
} from "o1js";

export const MAX_MISSION_EVENTS = 4;

export class MissionCompliancePublicInput extends Struct({
  missionIdHash: Field,
  authCommitment: Field,
  capabilityCommitment: Field,
  policyCommitment: Field,
  approvalCommitment: Field,
  holderKeyCommitment: Field,
  domainVerifierKeyCommitment: Field,
  allowedActionsRoot: Field,
  allowedDomainsRoot: Field,
  datasetCommitment: Field,
  domainProofCommitment: Field,
  outputCommitment: Field,
  paymentContextDigest: Field,
  traceRoot: Field,
  receiptCommitment: Field,
  nullifier: Field,
  validUntilSlot: UInt32,
  lastObservedSlot: UInt32,
  maxSpendMicrousd: UInt64,
  totalSpendMicrousd: UInt64,
  eventCount: UInt32,
  beneficiary: PublicKey,
  payoutNanomina: UInt64,
  protocolFeeNanomina: UInt64
}) {}

export class MissionBoundaryEventWitness extends Struct({
  enabled: Bool,
  actionKey: Field,
  domainKey: Field,
  resourceCommitment: Field,
  paymentContextDigest: Field,
  spendMicrousd: UInt64,
  observedSlot: UInt32,
  eventNonce: Field,
  holderSignature: Signature,
  actionWitness: MerkleMapWitness,
  domainWitness: MerkleMapWitness
}) {}

export class MissionComplianceWitness extends Struct({
  principalCommitment: Field,
  agentCommitment: Field,
  capabilityNonce: Field,
  policyNonce: Field,
  nullifierSecret: Field,
  receiptNonce: Field,
  holderPublicKey: PublicKey,
  domainVerifierPublicKey: PublicKey,
  domainProofSignature: Signature,
  events: Provable.Array(MissionBoundaryEventWitness, MAX_MISSION_EVENTS)
}) {}

export function missionPolicyCommitment(
  input: Pick<
    MissionCompliancePublicInput,
    | "allowedActionsRoot"
    | "allowedDomainsRoot"
    | "datasetCommitment"
    | "domainVerifierKeyCommitment"
    | "validUntilSlot"
    | "maxSpendMicrousd"
    | "beneficiary"
    | "payoutNanomina"
    | "protocolFeeNanomina"
  >,
  policyNonce: Field
) {
  return Poseidon.hash([
    input.allowedActionsRoot,
    input.allowedDomainsRoot,
    input.datasetCommitment,
    input.domainVerifierKeyCommitment,
    input.validUntilSlot.value,
    input.maxSpendMicrousd.value,
    ...input.beneficiary.toFields(),
    input.payoutNanomina.value,
    input.protocolFeeNanomina.value,
    policyNonce
  ]);
}

export function domainProofAttestationMessage(
  input: Pick<
    MissionCompliancePublicInput,
    | "missionIdHash"
    | "capabilityCommitment"
    | "policyCommitment"
    | "datasetCommitment"
    | "domainProofCommitment"
    | "outputCommitment"
  >
) {
  return Poseidon.hash([
    input.missionIdHash,
    input.capabilityCommitment,
    input.policyCommitment,
    input.datasetCommitment,
    input.domainProofCommitment,
    input.outputCommitment
  ]);
}

export function missionCapabilityCommitment(
  input: Pick<
    MissionCompliancePublicInput,
    "missionIdHash" | "authCommitment" | "holderKeyCommitment" | "policyCommitment"
  >,
  principalCommitment: Field,
  agentCommitment: Field,
  capabilityNonce: Field
) {
  return Poseidon.hash([
    input.missionIdHash,
    input.authCommitment,
    principalCommitment,
    agentCommitment,
    input.holderKeyCommitment,
    input.policyCommitment,
    capabilityNonce
  ]);
}

export function missionApprovalCommitment(
  input: Pick<
    MissionCompliancePublicInput,
    "authCommitment" | "capabilityCommitment" | "policyCommitment" | "validUntilSlot"
  >
) {
  return Poseidon.hash([
    input.authCommitment,
    input.capabilityCommitment,
    input.policyCommitment,
    input.validUntilSlot.value
  ]);
}

export function missionReceiptCommitment(
  input: Pick<
    MissionCompliancePublicInput,
    | "missionIdHash"
    | "capabilityCommitment"
    | "policyCommitment"
    | "traceRoot"
    | "datasetCommitment"
    | "domainProofCommitment"
    | "outputCommitment"
    | "paymentContextDigest"
    | "nullifier"
    | "beneficiary"
    | "payoutNanomina"
    | "protocolFeeNanomina"
    | "totalSpendMicrousd"
  >,
  receiptNonce: Field
) {
  return Poseidon.hash([
    input.missionIdHash,
    input.capabilityCommitment,
    input.policyCommitment,
    input.traceRoot,
    input.datasetCommitment,
    input.domainProofCommitment,
    input.outputCommitment,
    input.paymentContextDigest,
    input.nullifier,
    ...input.beneficiary.toFields(),
    input.payoutNanomina.value,
    input.protocolFeeNanomina.value,
    input.totalSpendMicrousd.value,
    receiptNonce
  ]);
}

export function missionBoundaryEventHash(
  input: Pick<
    MissionCompliancePublicInput,
    "missionIdHash" | "capabilityCommitment" | "policyCommitment"
  >,
  previousEventHash: Field,
  event: MissionBoundaryEventWitness
) {
  return Poseidon.hash([
    input.missionIdHash,
    input.capabilityCommitment,
    input.policyCommitment,
    previousEventHash,
    event.actionKey,
    event.domainKey,
    event.resourceCommitment,
    event.paymentContextDigest,
    event.spendMicrousd.value,
    event.observedSlot.value,
    event.eventNonce
  ]);
}

export const MissionComplianceProgram = ZkProgram({
  name: "mba-mission-compliance-v1",
  publicInput: MissionCompliancePublicInput,
  methods: {
    proveCompliance: {
      privateInputs: [MissionComplianceWitness],
      async method(
        input: MissionCompliancePublicInput,
        witness: MissionComplianceWitness
      ) {
        input.missionIdHash.assertNotEquals(Field(0));
        input.authCommitment.assertNotEquals(Field(0));
        input.domainVerifierKeyCommitment.assertNotEquals(Field(0));
        input.datasetCommitment.assertNotEquals(Field(0));
        input.domainProofCommitment.assertNotEquals(Field(0));
        input.outputCommitment.assertNotEquals(Field(0));
        input.paymentContextDigest.assertNotEquals(Field(0));
        input.payoutNanomina.assertGreaterThan(UInt64.zero);
        input.protocolFeeNanomina.assertGreaterThan(UInt64.zero);

        const holderKeyCommitment = Poseidon.hash(
          witness.holderPublicKey.toFields()
        );
        holderKeyCommitment.assertEquals(input.holderKeyCommitment);
        Poseidon.hash(
          witness.domainVerifierPublicKey.toFields()
        ).assertEquals(input.domainVerifierKeyCommitment);
        witness.domainProofSignature
          .verify(witness.domainVerifierPublicKey, [
            domainProofAttestationMessage(input)
          ])
          .assertTrue("domain proof verifier signature is invalid");

        missionPolicyCommitment(input, witness.policyNonce).assertEquals(
          input.policyCommitment
        );
        missionCapabilityCommitment(
          input,
          witness.principalCommitment,
          witness.agentCommitment,
          witness.capabilityNonce
        ).assertEquals(input.capabilityCommitment);
        missionApprovalCommitment(input).assertEquals(input.approvalCommitment);

        Poseidon.hash([
          input.capabilityCommitment,
          input.missionIdHash,
          witness.nullifierSecret
        ]).assertEquals(input.nullifier);

        let currentEventHash = Field(0);
        let traceRoot = Field(0);
        let currentPaymentContext = Field(0);
        let totalSpend = UInt64.zero;
        let eventCount = UInt32.zero;
        let disabledSlotSeen = Bool(false);
        let lastObservedSlot = UInt32.zero;

        for (const event of witness.events) {
          event.enabled
            .and(disabledSlotSeen)
            .assertFalse("enabled events must be contiguous");

          const [actionRoot, actionKey] =
            event.actionWitness.computeRootAndKey(Field(1));
          const [domainRoot, domainKey] =
            event.domainWitness.computeRootAndKey(Field(1));
          Provable.if(
            event.enabled,
            actionRoot.equals(input.allowedActionsRoot),
            Bool(true)
          ).assertTrue("action is outside mission allowlist");
          Provable.if(
            event.enabled,
            actionKey.equals(event.actionKey),
            Bool(true)
          ).assertTrue("action witness key mismatch");
          Provable.if(
            event.enabled,
            domainRoot.equals(input.allowedDomainsRoot),
            Bool(true)
          ).assertTrue("domain is outside mission allowlist");
          Provable.if(
            event.enabled,
            domainKey.equals(event.domainKey),
            Bool(true)
          ).assertTrue("domain witness key mismatch");
          Provable.if(
            event.enabled,
            event.observedSlot.lessThanOrEqual(input.validUntilSlot),
            Bool(true)
          ).assertTrue("boundary event is after mission expiry");
          Provable.if(
            event.enabled,
            event.observedSlot.greaterThanOrEqual(lastObservedSlot),
            Bool(true)
          ).assertTrue("boundary event slots must be monotonic");

          const eventHash = missionBoundaryEventHash(
            input,
            currentEventHash,
            event
          );
          Provable.if(
            event.enabled,
            event.holderSignature.verify(witness.holderPublicKey, [eventHash]),
            Bool(true)
          ).assertTrue("holder signature is invalid");

          currentEventHash = Provable.if(
            event.enabled,
            eventHash,
            currentEventHash
          );
          traceRoot = Provable.if(
            event.enabled,
            Poseidon.hash([traceRoot, eventHash]),
            traceRoot
          );
          currentPaymentContext = Provable.if(
            event.enabled,
            event.paymentContextDigest,
            currentPaymentContext
          );
          totalSpend = Provable.if(
            event.enabled,
            totalSpend.add(event.spendMicrousd),
            totalSpend
          );
          eventCount = Provable.if(
            event.enabled,
            eventCount.add(1),
            eventCount
          );
          lastObservedSlot = Provable.if(
            event.enabled,
            event.observedSlot,
            lastObservedSlot
          );
          disabledSlotSeen = disabledSlotSeen.or(event.enabled.not());
        }

        eventCount.assertGreaterThan(UInt32.zero);
        totalSpend
          .lessThanOrEqual(input.maxSpendMicrousd)
          .assertTrue("mission spend exceeds approved maximum");
        traceRoot.assertEquals(input.traceRoot);
        currentPaymentContext.assertEquals(input.paymentContextDigest);
        totalSpend.assertEquals(input.totalSpendMicrousd);
        eventCount.assertEquals(input.eventCount);
        lastObservedSlot.assertEquals(input.lastObservedSlot);
        missionReceiptCommitment(input, witness.receiptNonce).assertEquals(
          input.receiptCommitment
        );
      }
    }
  }
});

export class MissionComplianceProof extends ZkProgram.Proof(
  MissionComplianceProgram
) {}
