import "reflect-metadata";

import assert from "node:assert/strict";
import { PrivateKey } from "o1js";

import {
  buildMissionCapability,
  jwks,
  missionComplianceStatement,
  sha256Hex,
  verifyReceiptCapabilityBinding,
  verifyReceiptDomainProof
} from "../packages/protocol/index.js";
import {
  buildMissionComplianceInputs,
  createDomainProofAttestation,
  prepareMissionComplianceBinding,
  validateZekoCapabilityBinding,
  zekoHolderKeyCommitment
} from "../packages/protocol/zeko-inputs.js";
import {
  MissionComplianceProgram
} from "../dist-zkapp/MissionComplianceProgram.js";

MissionComplianceProgram.setProofsEnabled(false);

const holderPrivateKey = PrivateKey.random();
const domainVerifierPrivateKey = PrivateKey.random();
const beneficiary = PrivateKey.random().toPublicKey();
const missionIdHash = sha256Hex("mission-input-compiler");
const authCommitment = sha256Hex("enterprise-auth-commitment");
const allowedActions = ["private_compute.run", "x402.settle"];
const allowedDomains = ["compute.example"];
const prepared = await prepareMissionComplianceBinding({
  holderPrivateKey,
  domainVerifierPublicKey:
    domainVerifierPrivateKey.toPublicKey(),
  beneficiary,
  missionIdHash,
  authCommitment,
  principalHash: sha256Hex("principal"),
  agentId: "agent-input-compiler",
  datasetId: "dataset-private-1",
  dataScopes: ["dataset:private-1"],
  allowedActions,
  allowedDomains,
  validUntilSlot: 500,
  maxSpendUsd: "2.00",
  payoutNative: "0.015",
  protocolFeeNative: "0.001"
});

assert.equal(
  prepared.binding.holderKeyCommitment,
  zekoHolderKeyCommitment(holderPrivateKey.toPublicKey())
);
assert.equal(prepared.binding.networkName, "Zeko Ethereum Sepolia");
assert.equal(prepared.binding.signingNetworkId, "testnet");
assert.equal(prepared.binding.nativeAsset.symbol, "sETH");
assert.equal(prepared.binding.nativeAsset.decimals, 9);
assert.equal(
  prepared.binding.payoutNativeUnits,
  prepared.binding.payoutNanomina
);
assert.equal(
  prepared.binding.protocolFeeNativeUnits,
  prepared.binding.protocolFeeNanomina
);
assert.equal(
  validateZekoCapabilityBinding(prepared.binding, {
    missionIdHash,
    authCommitment,
    allowedActions,
    allowedDomains,
    maxSpendUsd: "2.00"
  }).valid,
  true
);

const capability = buildMissionCapability({
  issuer: "https://authority.example/",
  audience: "mission-verifier",
  principalHash: sha256Hex("principal"),
  authCommitment,
  identityAttestationHash: sha256Hex("identity"),
  agentId: "agent-input-compiler",
  holderKeyCommitment: sha256Hex("ed25519-holder-key"),
  zekoBinding: prepared.binding,
  missionId: "mission-input-compiler",
  missionIdHash,
  approvalHash: sha256Hex("approval"),
  policyHash: sha256Hex("policy"),
  allowedActions,
  allowedDomains,
  dataScopes: ["dataset:private-1"],
  paymentRails: ["zeko"],
  maxSpendUsd: "2.00",
  expiresAt: new Date(Date.now() + 600_000).toISOString(),
  nullifierCommitment: sha256Hex("holder-nullifier-commitment")
});

const domainProofEvidence = {
  version: "domain-proof-v1",
  domain: "compute.example",
  verifier: "independent-verifier"
};
const output = {
  version: "private-output-v1",
  aggregate: 42
};
const domainProof = await createDomainProofAttestation({
  capability,
  domainVerifierPrivateKey,
  evidence: domainProofEvidence,
  output
});
const compiled = await buildMissionComplianceInputs({
  capability,
  privateWitnessMaterial: prepared.privateWitnessMaterial,
  domainProof,
  output,
  events: [
    {
      action: "private_compute.run",
      domain: "compute.example",
      resource: { datasetId: "dataset-private-1" },
      paymentContext: { rail: "zeko", phase: "reserve" },
      spendUsd: "0.40",
      observedSlot: 100
    },
    {
      action: "x402.settle",
      domain: "compute.example",
      resource: { receiptId: "receipt-input-compiler" },
      paymentContext: { rail: "zeko", phase: "settle" },
      spendUsd: "0.60",
      observedSlot: 101
    }
  ]
});

assert.equal(
  compiled.publicInput.approvalCommitment.toString(),
  prepared.binding.approvalCommitment
);
assert.equal(compiled.totalSpendMicrousd, "1000000");
const { proof } = await MissionComplianceProgram.proveCompliance(
  compiled.publicInput,
  compiled.witness
);
assert.equal(await MissionComplianceProgram.verify(proof), true);
const zekoStatement =
  missionComplianceStatement(compiled.publicInput);
const capabilityBoundReceipt = {
  capabilityArtifact: capability,
  mission: {
    capabilityHash: capability.capabilityHash,
    authCommitment: capability.authCommitment,
    approvalCommitment:
      capability.zekoBinding.approvalCommitment
  },
  policy: { policyHash: capability.policyHash },
  holder: {
    keyThumbprint: capability.holderKeyCommitment
  },
  payment: {
    paymentContextDigest:
      zekoStatement.paymentContextDigest
  },
  nullifier: zekoStatement.nullifier,
  zekoStatement
};
assert.equal(
  verifyReceiptCapabilityBinding(capabilityBoundReceipt, {
    authorityJwks: jwks()
  }).valid,
  true
);
assert.equal(
  verifyReceiptCapabilityBinding(
    {
      ...capabilityBoundReceipt,
      nullifier: "different-nullifier"
    },
    { authorityJwks: jwks() }
  ).valid,
  false
);
const domainProofReceipt = {
  domainProof,
  zekoStatement
};
assert.equal(
  (await verifyReceiptDomainProof(domainProofReceipt)).valid,
  false
);
assert.equal(
  (
    await verifyReceiptDomainProof(domainProofReceipt, {
      domainProofVerifier: async (evidence) => ({
        valid:
          evidence.verifier === "independent-verifier",
        verifier: "test-domain-verifier"
      })
    })
  ).valid,
  true
);
assert.equal(
  (
    await verifyReceiptDomainProof(
      {
        ...domainProofReceipt,
        domainProof: {
          ...domainProofReceipt.domainProof,
          evidence: {
            ...domainProofReceipt.domainProof.evidence,
            verifier: "attacker"
          }
        }
      },
      { domainProofVerifier: async () => true }
    )
  ).valid,
  false
);

const tamperedRoot = {
  ...prepared.binding,
  allowedActionsRoot: prepared.binding.allowedDomainsRoot
};
assert.equal(
  validateZekoCapabilityBinding(tamperedRoot, {
    missionIdHash,
    authCommitment,
    allowedActions,
    allowedDomains,
    maxSpendUsd: "2.00"
  }).valid,
  false
);
await assert.rejects(
  () =>
    buildMissionComplianceInputs({
      capability: {
        ...capability,
        zekoBinding: {
          ...capability.zekoBinding,
          holderPublicKey: PrivateKey.random().toPublicKey().toBase58()
        }
      },
      privateWitnessMaterial: prepared.privateWitnessMaterial,
      domainProof,
      output,
      events: [
        {
          action: "private_compute.run",
          domain: "compute.example",
          resource: "dataset-private-1",
          paymentContext: "reserve",
          spendUsd: "0.40",
          observedSlot: 100
        }
      ]
    }),
  /holder key commitment|private key/i
);
await assert.rejects(
  () =>
    buildMissionComplianceInputs({
      capability,
      privateWitnessMaterial: prepared.privateWitnessMaterial,
      domainProof,
      output,
      events: [
        {
          action: "email.send",
          domain: "compute.example",
          resource: "message",
          paymentContext: "none",
          spendUsd: "0",
          observedSlot: 100
        }
      ]
    }),
  /outside the capability/
);
await assert.rejects(
  () =>
    buildMissionComplianceInputs({
      capability,
      privateWitnessMaterial: prepared.privateWitnessMaterial,
      domainProof,
      output,
      events: [
        {
          action: "private_compute.run",
          domain: "compute.example",
          resource: "dataset-private-1",
          paymentContext: "reserve",
          spendUsd: "0.10",
          observedSlot: 101
        },
        {
          action: "x402.settle",
          domain: "compute.example",
          resource: "receipt",
          paymentContext: "settle",
          spendUsd: "0.10",
          observedSlot: 100
        }
      ]
    }),
  /monotonic/
);

console.log(
  JSON.stringify(
    {
      ok: true,
      checks: [
        "offchain-ed25519-to-pallas-passport-binding",
        "canonical-action-and-domain-roots",
        "authority-capability-to-circuit-binding",
        "receipt-capability-and-nullifier-binding",
        "proof-ready-witness-compilation",
        "holder-signed-boundary-events",
        "trace-and-spend-aggregation",
        "domain-proof-binding-and-verifier",
        "tampered-root-rejection",
        "wrong-holder-rejection",
        "out-of-scope-action-rejection",
        "non-monotonic-slot-rejection"
      ]
    },
    null,
    2
  )
);
