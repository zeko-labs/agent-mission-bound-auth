import "reflect-metadata";

import {
  AccountUpdate,
  Bool,
  Field,
  MerkleMap,
  Mina,
  Poseidon,
  PrivateKey,
  Signature,
  UInt32,
  UInt64
} from "o1js";

import {
  MAX_MISSION_EVENTS,
  MissionBoundaryEventWitness,
  MissionComplianceProgram,
  MissionComplianceProof,
  MissionCompliancePublicInput,
  MissionComplianceWitness,
  domainProofAttestationMessage,
  missionApprovalCommitment,
  missionBoundaryEventHash,
  missionCapabilityCommitment,
  missionPolicyCommitment,
  missionReceiptCommitment
} from "../dist-zkapp/MissionComplianceProgram.js";
import {
  MissionEscrow,
  MissionRegistry,
  MissionRegistryConfig,
  approvalAuthorizationMessage,
  approvalRegistryKey,
  nullifierRegistryKey,
  receiptRegistryKey,
  revocationAuthorizationMessage,
  revocationRegistryKey
} from "../dist-zkapp/MissionRegistry.js";
import {
  buildMissionComplianceProofArtifact,
  verifyMissionComplianceProofArtifact
} from "../packages/protocol/zeko-proof.js";

const proofsEnabled = process.env.MBA_REAL_PROOFS === "true";
MissionComplianceProgram.setProofsEnabled(proofsEnabled);

function publicInput(values = {}) {
  return new MissionCompliancePublicInput({
    missionIdHash: values.missionIdHash ?? Field(11),
    authCommitment: values.authCommitment ?? Field(12),
    capabilityCommitment: values.capabilityCommitment ?? Field(0),
    policyCommitment: values.policyCommitment ?? Field(0),
    approvalCommitment: values.approvalCommitment ?? Field(0),
    holderKeyCommitment: values.holderKeyCommitment ?? Field(0),
    domainVerifierKeyCommitment:
      values.domainVerifierKeyCommitment ?? Field(0),
    allowedActionsRoot: values.allowedActionsRoot ?? Field(0),
    allowedDomainsRoot: values.allowedDomainsRoot ?? Field(0),
    datasetCommitment: values.datasetCommitment ?? Field(13),
    domainProofCommitment: values.domainProofCommitment ?? Field(14),
    outputCommitment: values.outputCommitment ?? Field(15),
    paymentContextDigest: values.paymentContextDigest ?? Field(0),
    traceRoot: values.traceRoot ?? Field(0),
    receiptCommitment: values.receiptCommitment ?? Field(0),
    nullifier: values.nullifier ?? Field(0),
    validUntilSlot: values.validUntilSlot ?? UInt32.from(500),
    lastObservedSlot: values.lastObservedSlot ?? UInt32.zero,
    maxSpendMicrousd: values.maxSpendMicrousd ?? UInt64.from(2_000_000),
    totalSpendMicrousd: values.totalSpendMicrousd ?? UInt64.zero,
    eventCount: values.eventCount ?? UInt32.zero,
    beneficiary: values.beneficiary,
    payoutNanomina: values.payoutNanomina ?? UInt64.from(15_000_000),
    protocolFeeNanomina:
      values.protocolFeeNanomina ?? UInt64.from(1_000_000)
  });
}

function buildFixture(
  beneficiary,
  observedSlots = [100, 101],
  invalidDomainProofSignature = false
) {
  const holderKey = PrivateKey.random();
  const holderPublicKey = holderKey.toPublicKey();
  const domainVerifierKey = PrivateKey.random();
  const domainVerifierPublicKey =
    domainVerifierKey.toPublicKey();
  const actionMap = new MerkleMap();
  const domainMap = new MerkleMap();
  const actionKeys = [Field(101), Field(102)];
  const domainKeys = [Field(201), Field(202)];
  for (const key of actionKeys) actionMap.set(key, Field(1));
  for (const key of domainKeys) domainMap.set(key, Field(1));

  const privateValues = {
    principalCommitment: Field(21),
    agentCommitment: Field(22),
    capabilityNonce: Field(23),
    policyNonce: Field(24),
    nullifierSecret: Field(25),
    receiptNonce: Field(26)
  };

  let input = publicInput({
    beneficiary,
    holderKeyCommitment: Poseidon.hash(holderPublicKey.toFields()),
    domainVerifierKeyCommitment: Poseidon.hash(
      domainVerifierPublicKey.toFields()
    ),
    allowedActionsRoot: actionMap.getRoot(),
    allowedDomainsRoot: domainMap.getRoot()
  });
  input.policyCommitment = missionPolicyCommitment(
    input,
    privateValues.policyNonce
  );
  input.capabilityCommitment = missionCapabilityCommitment(
    input,
    privateValues.principalCommitment,
    privateValues.agentCommitment,
    privateValues.capabilityNonce
  );
  input.approvalCommitment = missionApprovalCommitment(input);
  input.nullifier = Poseidon.hash([
    input.capabilityCommitment,
    input.missionIdHash,
    privateValues.nullifierSecret
  ]);

  const enabledSpecs = [
    {
      actionKey: actionKeys[0],
      domainKey: domainKeys[0],
      resourceCommitment: Field(301),
      paymentContextDigest: Field(401),
      spendMicrousd: UInt64.from(400_000),
      observedSlot: UInt32.from(observedSlots[0]),
      eventNonce: Field(501)
    },
    {
      actionKey: actionKeys[1],
      domainKey: domainKeys[1],
      resourceCommitment: Field(302),
      paymentContextDigest: Field(402),
      spendMicrousd: UInt64.from(600_000),
      observedSlot: UInt32.from(observedSlots[1]),
      eventNonce: Field(502)
    }
  ];

  const events = [];
  let currentEventHash = Field(0);
  let traceRoot = Field(0);
  let totalSpend = UInt64.zero;
  for (const spec of enabledSpecs) {
    const unsigned = new MissionBoundaryEventWitness({
      enabled: Bool(true),
      ...spec,
      holderSignature: Signature.create(holderKey, [Field(0)]),
      actionWitness: actionMap.getWitness(spec.actionKey),
      domainWitness: domainMap.getWitness(spec.domainKey)
    });
    const eventHash = missionBoundaryEventHash(
      input,
      currentEventHash,
      unsigned
    );
    const event = new MissionBoundaryEventWitness({
      ...unsigned,
      holderSignature: Signature.create(holderKey, [eventHash])
    });
    events.push(event);
    currentEventHash = eventHash;
    traceRoot = Poseidon.hash([traceRoot, eventHash]);
    totalSpend = totalSpend.add(event.spendMicrousd);
  }

  const dummyKey = PrivateKey.random();
  while (events.length < MAX_MISSION_EVENTS) {
    events.push(
      new MissionBoundaryEventWitness({
        enabled: Bool(false),
        actionKey: Field(0),
        domainKey: Field(0),
        resourceCommitment: Field(0),
        paymentContextDigest: Field(0),
        spendMicrousd: UInt64.zero,
        observedSlot: UInt32.zero,
        eventNonce: Field(0),
        holderSignature: Signature.create(dummyKey, [Field(0)]),
        actionWitness: actionMap.getWitness(Field(0)),
        domainWitness: domainMap.getWitness(Field(0))
      })
    );
  }

  input.traceRoot = traceRoot;
  input.paymentContextDigest =
    enabledSpecs[enabledSpecs.length - 1].paymentContextDigest;
  input.totalSpendMicrousd = totalSpend;
  input.eventCount = UInt32.from(enabledSpecs.length);
  input.lastObservedSlot =
    enabledSpecs[enabledSpecs.length - 1].observedSlot;
  input.receiptCommitment = missionReceiptCommitment(
    input,
    privateValues.receiptNonce
  );

  return {
    holderKey,
    input,
    witness: new MissionComplianceWitness({
      ...privateValues,
      holderPublicKey,
      domainVerifierPublicKey,
      domainProofSignature: Signature.create(
        invalidDomainProofSignature
          ? PrivateKey.random()
          : domainVerifierKey,
        [domainProofAttestationMessage(input)]
      ),
      events
    })
  };
}

async function send(txPromise, keys) {
  const tx = await txPromise;
  await tx.prove();
  const sent = await tx.sign(keys).send();
  return sent;
}

let verificationKey = null;
let circuitDigest = null;
if (proofsEnabled) {
  ({ verificationKey } = await MissionComplianceProgram.compile());
  circuitDigest = await MissionComplianceProgram.digest();
  await MissionRegistry.compile();
}

const Local = await Mina.LocalBlockchain({ proofsEnabled });
Mina.setActiveInstance(Local);
const [deployer, payer, beneficiaryAccount, feeAccount, relayer] =
  Local.testAccounts;
const authorityKey = PrivateKey.random();
const zkappKey = PrivateKey.random();
const registry = new MissionRegistry(zkappKey.toPublicKey());
const fixture = buildFixture(beneficiaryAccount);
const { proof } = await MissionComplianceProgram.proveCompliance(
  fixture.input,
  fixture.witness
);
if (!(await MissionComplianceProgram.verify(proof))) {
  throw new Error("mission compliance proof did not verify");
}
let nonMonotonicTraceRejected = false;
try {
  const invalidFixture = buildFixture(beneficiaryAccount, [101, 100]);
  await MissionComplianceProgram.proveCompliance(
    invalidFixture.input,
    invalidFixture.witness
  );
} catch {
  nonMonotonicTraceRejected = true;
}
if (!nonMonotonicTraceRejected) {
  throw new Error("non-monotonic boundary event slots were accepted");
}
let invalidDomainProofAttestationRejected = false;
try {
  const invalidFixture = buildFixture(
    beneficiaryAccount,
    [100, 101],
    true
  );
  await MissionComplianceProgram.proveCompliance(
    invalidFixture.input,
    invalidFixture.witness
  );
} catch {
  invalidDomainProofAttestationRejected = true;
}
if (!invalidDomainProofAttestationRejected) {
  throw new Error("invalid domain proof attestation was accepted");
}
let proofArtifact = null;
if (proofsEnabled) {
  proofArtifact = buildMissionComplianceProofArtifact({
    proof,
    verificationKey,
    circuitDigest
  });
  const artifactCheck = await verifyMissionComplianceProofArtifact(
    proofArtifact,
    {
      verificationKey,
      circuitDigest,
      proofClass: MissionComplianceProof
    }
  );
  if (!artifactCheck.valid) {
    throw new Error(artifactCheck.reason);
  }
}

await send(
  Mina.transaction(deployer, async () => {
    AccountUpdate.fundNewAccount(deployer);
    await registry.deploy();
  }),
  [deployer.key, zkappKey]
);
await send(
  Mina.transaction(deployer, async () => {
    await registry.configure(
      new MissionRegistryConfig({
        authorityKey: authorityKey.toPublicKey(),
        protocolFeeRecipient: feeAccount
      })
    );
  }),
  [deployer.key, zkappKey]
);

const registryMap = new MerkleMap();
const authoritySignature = Signature.create(authorityKey, [
  ...approvalAuthorizationMessage(
    registry.address,
    UInt64.zero,
    fixture.input.capabilityCommitment,
    fixture.input.approvalCommitment
  )
]);
const approvalKey = approvalRegistryKey(
  fixture.input.capabilityCommitment
);
const approvalWitness = registryMap.getWitness(approvalKey);
await send(
  Mina.transaction(relayer, async () => {
    await registry.anchorApproval(
      fixture.input.capabilityCommitment,
      fixture.input.approvalCommitment,
      authoritySignature,
      approvalWitness
    );
  }),
  [relayer.key]
);
registryMap.set(approvalKey, fixture.input.approvalCommitment);
registry.sequence.get().assertEquals(UInt64.from(1));

const escrow = new MissionEscrow({
  missionIdHash: fixture.input.missionIdHash,
  payer,
  beneficiary: beneficiaryAccount,
  amountNanomina: fixture.input.payoutNanomina.add(
    fixture.input.protocolFeeNanomina
  ),
  refundAfterSlot: UInt32.from(501),
  escrowNonce: Field(601)
});
const escrowWitness = registryMap.getWitness(escrow.key());
await send(
  Mina.transaction(payer, async () => {
    await registry.fundMission(escrow, escrowWitness);
  }),
  [payer.key]
);
registryMap.set(escrow.key(), escrow.leaf());
registry.sequence.get().assertEquals(UInt64.from(2));

const beneficiaryBefore = Mina.getBalance(beneficiaryAccount);
const feeBefore = Mina.getBalance(feeAccount);
const revocationKey = revocationRegistryKey(
  fixture.input.capabilityCommitment
);
const nullifierKey = nullifierRegistryKey(fixture.input.nullifier);
const receiptKey = receiptRegistryKey(
  fixture.input.receiptCommitment
);
const settlementWitnesses = {
  approval: registryMap.getWitness(approvalKey),
  revocation: registryMap.getWitness(revocationKey),
  nullifier: registryMap.getWitness(nullifierKey)
};
registryMap.set(nullifierKey, Field(1));
settlementWitnesses.receipt = registryMap.getWitness(receiptKey);
registryMap.set(
  receiptKey,
  Poseidon.hash([
    fixture.input.receiptCommitment,
    fixture.input.nullifier,
    fixture.input.paymentContextDigest,
    ...fixture.input.beneficiary.toFields(),
    fixture.input.payoutNanomina.value,
    fixture.input.protocolFeeNanomina.value
  ])
);
settlementWitnesses.escrow = registryMap.getWitness(escrow.key());
registryMap.set(escrow.key(), escrow.leaf(Field(2)));
Local.setGlobalSlot(100);
let futureEventSettlementRejected = false;
try {
  await send(
    Mina.transaction(relayer, async () => {
      await registry.settleMission(
        proof,
        escrow,
        settlementWitnesses.approval,
        settlementWitnesses.revocation,
        settlementWitnesses.nullifier,
        settlementWitnesses.receipt,
        settlementWitnesses.escrow
      );
    }),
    [relayer.key]
  );
} catch {
  futureEventSettlementRejected = true;
}
if (!futureEventSettlementRejected) {
  throw new Error("settlement accepted a future boundary event");
}
Local.setGlobalSlot(101);
await send(
  Mina.transaction(relayer, async () => {
    await registry.settleMission(
      proof,
      escrow,
      settlementWitnesses.approval,
      settlementWitnesses.revocation,
      settlementWitnesses.nullifier,
      settlementWitnesses.receipt,
      settlementWitnesses.escrow
    );
  }),
  [relayer.key]
);

const beneficiaryAfter = Mina.getBalance(beneficiaryAccount);
const feeAfter = Mina.getBalance(feeAccount);
beneficiaryAfter
  .sub(beneficiaryBefore)
  .assertEquals(fixture.input.payoutNanomina);
feeAfter.sub(feeBefore).assertEquals(fixture.input.protocolFeeNanomina);
registry.registryRoot.get().assertEquals(registryMap.getRoot());
registry.sequence.get().assertEquals(UInt64.from(3));

let replayRejected = false;
try {
  await send(
    Mina.transaction(relayer, async () => {
      await registry.settleMission(
        proof,
        escrow,
        registryMap.getWitness(approvalKey),
        registryMap.getWitness(revocationKey),
        registryMap.getWitness(nullifierKey),
        registryMap.getWitness(receiptKey),
        registryMap.getWitness(escrow.key())
      );
    }),
    [relayer.key]
  );
} catch {
  replayRejected = true;
}
if (!replayRejected) throw new Error("duplicate settlement was not rejected");

const revocationWitness = registryMap.getWitness(revocationKey);
let invalidRevocationRejected = false;
try {
  await send(
    Mina.transaction(relayer, async () => {
      await registry.revokeCapability(
        fixture.input.capabilityCommitment,
        Signature.create(PrivateKey.random(), [
          ...revocationAuthorizationMessage(
            registry.address,
            UInt64.from(3),
            fixture.input.capabilityCommitment
          )
        ]),
        revocationWitness
      );
    }),
    [relayer.key]
  );
} catch {
  invalidRevocationRejected = true;
}
if (!invalidRevocationRejected) {
  throw new Error("invalid revocation authority signature was accepted");
}
await send(
  Mina.transaction(relayer, async () => {
    await registry.revokeCapability(
      fixture.input.capabilityCommitment,
      Signature.create(authorityKey, [
        ...revocationAuthorizationMessage(
          registry.address,
          UInt64.from(3),
          fixture.input.capabilityCommitment
        )
      ]),
      revocationWitness
    );
  }),
  [relayer.key]
);
registryMap.set(revocationKey, Field(1));
registry.registryRoot.get().assertEquals(registryMap.getRoot());
registry.sequence.get().assertEquals(UInt64.from(4));

const refundableEscrow = new MissionEscrow({
  missionIdHash: Field(701),
  payer,
  beneficiary: beneficiaryAccount,
  amountNanomina: UInt64.from(5_000_000),
  refundAfterSlot: UInt32.from(200),
  escrowNonce: Field(702)
});
await send(
  Mina.transaction(payer, async () => {
    await registry.fundMission(
      refundableEscrow,
      registryMap.getWitness(refundableEscrow.key())
    );
  }),
  [payer.key]
);
registryMap.set(refundableEscrow.key(), refundableEscrow.leaf());
registry.sequence.get().assertEquals(UInt64.from(5));
Local.setGlobalSlot(201);
await send(
  Mina.transaction(relayer, async () => {
    await registry.refundMission(
      refundableEscrow,
      registryMap.getWitness(refundableEscrow.key())
    );
  }),
  [relayer.key]
);
registryMap.set(
  refundableEscrow.key(),
  refundableEscrow.leaf(Field(3))
);
registry.registryRoot.get().assertEquals(registryMap.getRoot());
registry.sequence.get().assertEquals(UInt64.from(6));

console.log(
  JSON.stringify(
    {
      ok: true,
      proofsEnabled,
      proofArtifactHash: proofArtifact?.artifactHash ?? null,
      checks: [
    "holder-signature",
    "domain-proof-verifier-signature",
        "action-membership",
        "domain-membership",
        "trace-chain",
        "monotonic-event-slots",
        "slot-expiry",
        "aggregate-budget",
        "approval-signature",
        "approval-membership",
        "revocation-non-membership",
        "escrow-funding",
        "proof-gated-payout",
        "future-event-settlement-rejected",
        "protocol-fee-split",
        "receipt-root",
        "nullifier-consumption",
        "duplicate-settlement-rejected",
        ...(proofsEnabled ? ["serialized-proof-artifact-verification"] : []),
        "invalid-revocation-signature-rejected",
        "on-chain-capability-revocation",
        "expired-escrow-refund"
      ],
      roots: {
        registry: registryMap.getRoot().toString()
      }
    },
    null,
    2
  )
);
