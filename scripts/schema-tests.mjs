import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { PrivateKey } from "o1js";
import Ajv2020 from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import {
  buildMissionCapability
} from "../packages/protocol/capabilities.js";
import {
  buildEnterpriseIdentityAttestation
} from "../packages/protocol/identity-attestations.js";
import {
  validateArtifactSchema
} from "../packages/protocol/schema-validation.js";
import {
  buildZekoRegistryAnchor
} from "../packages/protocol/zeko-chain.js";

const schemaDirectory = path.resolve("schemas");
const catalog = new Ajv2020({
  strict: true,
  allErrors: true,
  allowUnionTypes: true
});
addFormats(catalog);
for (const file of fs.readdirSync(schemaDirectory)) {
  if (!file.endsWith(".schema.json")) continue;
  catalog.addSchema(
    JSON.parse(fs.readFileSync(path.join(schemaDirectory, file), "utf8"))
  );
}
for (const file of fs.readdirSync(schemaDirectory)) {
  if (!file.endsWith(".schema.json")) continue;
  const schema = JSON.parse(
    fs.readFileSync(path.join(schemaDirectory, file), "utf8")
  );
  assert.ok(catalog.getSchema(schema.$id));
}

const normalizedClaims = {
  provider: "auth0",
  issuer: "https://tenant.example/",
  subject: "enterprise-user-1",
  audience: "mba-client",
  agentId: "agent-1",
  organization: "Zeko Labs",
  represents: { type: "organization", id: "zeko-labs" },
  scopes: ["compute:private"],
  computeScopes: ["compute:private"],
  datasetScopes: [],
  railScopes: ["rail:zeko"],
  budget: { maxSpendUsd: "1.00" },
  tokenHash: "a".repeat(64),
  expiresAt: new Date(Date.now() + 60_000).toISOString()
};
const identity = buildEnterpriseIdentityAttestation({
  normalizedClaims,
  authCommitment: "b".repeat(64),
  scopeCommitment: "c".repeat(64)
});
assert.equal(
  validateArtifactSchema("enterprise-identity-attestation", identity).valid,
  true
);
assert.equal(
  validateArtifactSchema("enterprise-identity-attestation", {
    ...identity,
    injected: true
  }).valid,
  false
);

const capability = buildMissionCapability({
  issuer: "https://mba.example/",
  audience: "mission-verifier",
  principalHash: "d".repeat(64),
  authCommitment: identity.authCommitment,
  identityAttestationHash: identity.attestationHash,
  agentId: normalizedClaims.agentId,
  holderKeyCommitment: "e".repeat(64),
  missionId: "mission-1",
  missionIdHash: "f".repeat(64),
  approvalHash: "1".repeat(64),
  policyHash: "2".repeat(64),
  allowedActions: ["private_compute.run"],
  paymentRails: ["zeko"],
  expiresAt: new Date(Date.now() + 60_000).toISOString()
});
assert.equal(validateArtifactSchema("capability", capability).valid, true);
assert.equal("nullifierSeed" in capability, false);
assert.equal(
  validateArtifactSchema("capability", {
    ...capability,
    nullifierSeed: "leaked"
  }).valid,
  false
);

const beneficiary = PrivateKey.random().toPublicKey().toBase58();
const statement = Object.fromEntries([
  "missionIdHash",
  "authCommitment",
  "capabilityCommitment",
  "policyCommitment",
  "approvalCommitment",
  "holderKeyCommitment",
  "domainVerifierKeyCommitment",
  "allowedActionsRoot",
  "allowedDomainsRoot",
  "datasetCommitment",
  "domainProofCommitment",
  "outputCommitment",
  "paymentContextDigest",
  "traceRoot",
  "receiptCommitment",
  "nullifier",
  "validUntilSlot",
  "lastObservedSlot",
  "maxSpendMicrousd",
  "totalSpendMicrousd",
  "eventCount",
  "payoutNanomina",
  "protocolFeeNanomina"
].map((field, index) => [field, String(index + 1)]));
statement.beneficiary = beneficiary;
const proofArtifact = {
  version: "mba-mission-compliance-proof-v1",
  proofSystem: "zeko-o1js-mission-compliance-v1",
  circuitDigest: "circuit",
  verificationKeyHash: "123",
  publicStatement: statement,
  proof: {
    publicInput: ["1"],
    publicOutput: [],
    maxProofsVerified: 0,
    proof: "base64-proof"
  },
  artifactHash: "3".repeat(64)
};
assert.equal(
  validateArtifactSchema("mission-compliance-proof", proofArtifact).valid,
  true
);

const anchor = buildZekoRegistryAnchor({
  registryAddress: PrivateKey.random().toPublicKey().toBase58(),
  transactionHash: "tx-hash",
  sequence: "2",
  registryRoot: "3",
  ...statement,
  proofArtifactHash: proofArtifact.artifactHash
});
assert.equal(
  validateArtifactSchema("zeko-registry-anchor", anchor).valid,
  true
);

console.log(JSON.stringify({
  ok: true,
  checks: [
    "all-schemas-compile-strict",
    "identity-attestation-schema",
    "unknown-field-rejection",
    "capability-hides-nullifier-secret",
    "proof-artifact-schema",
    "zeko-anchor-schema"
  ]
}, null, 2));
