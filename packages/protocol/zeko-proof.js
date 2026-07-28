import { sha256Hex } from "./digest.js";

export const MISSION_COMPLIANCE_PROOF_SYSTEM =
  "zeko-o1js-mission-compliance-v1";

const PUBLIC_INPUT_FIELDS = Object.freeze([
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
  "beneficiary",
  "payoutNanomina",
  "protocolFeeNanomina"
]);

function stringValue(value) {
  if (value?.toBase58) return value.toBase58();
  if (value?.toString) return value.toString();
  return String(value);
}

export function missionComplianceStatement(publicInput) {
  const statement = {};
  for (const field of PUBLIC_INPUT_FIELDS) {
    if (publicInput?.[field] === undefined) {
      throw new TypeError(`Mission compliance public input is missing ${field}.`);
    }
    statement[field] = stringValue(publicInput[field]);
  }
  return statement;
}

export function buildMissionComplianceProofArtifact(input = {}) {
  if (!input.proof?.toJSON) {
    throw new TypeError("A concrete o1js mission compliance proof is required.");
  }
  if (!input.verificationKey?.data || !input.verificationKey?.hash) {
    throw new TypeError("The compiled mission compliance verification key is required.");
  }
  if (
    input.circuitDigest === undefined ||
    input.circuitDigest === null ||
    String(input.circuitDigest).length === 0
  ) {
    throw new TypeError("The compiled mission compliance circuit digest is required.");
  }
  const proof = input.proof.toJSON();
  const publicStatement = missionComplianceStatement(
    input.publicInput ?? input.proof.publicInput
  );
  const body = {
    version: "mba-mission-compliance-proof-v1",
    proofSystem: MISSION_COMPLIANCE_PROOF_SYSTEM,
    circuitDigest: String(input.circuitDigest),
    verificationKeyHash: stringValue(input.verificationKey.hash),
    publicStatement,
    proof
  };
  return {
    ...body,
    artifactHash: sha256Hex(body)
  };
}

export async function verifyMissionComplianceProofArtifact(
  artifact,
  options = {}
) {
  if (!artifact || typeof artifact !== "object") {
    return { valid: false, reason: "Missing mission compliance proof artifact." };
  }
  if (artifact.version !== "mba-mission-compliance-proof-v1") {
    return { valid: false, reason: "Unsupported mission compliance proof artifact." };
  }
  if (artifact.proofSystem !== MISSION_COMPLIANCE_PROOF_SYSTEM) {
    return { valid: false, reason: "Unsupported mission compliance proof system." };
  }
  const { artifactHash, ...body } = artifact;
  if (artifactHash !== sha256Hex(body)) {
    return { valid: false, reason: "Mission compliance proof artifact hash mismatch." };
  }
  if (!artifact.proof || !artifact.publicStatement) {
    return { valid: false, reason: "Mission compliance proof or public statement is missing." };
  }
  if (options.expectedStatement) {
    for (const field of PUBLIC_INPUT_FIELDS) {
      const expected = options.expectedStatement[field];
      if (
        expected !== undefined &&
        artifact.publicStatement[field] !== stringValue(expected)
      ) {
        return {
          valid: false,
          reason: `Mission compliance public statement ${field} mismatch.`
        };
      }
    }
  }

  const verificationKey = options.verificationKey;
  if (!verificationKey?.data || !verificationKey?.hash) {
    return { valid: false, reason: "Trusted mission compliance verification key is required." };
  }
  if (artifact.verificationKeyHash !== stringValue(verificationKey.hash)) {
    return { valid: false, reason: "Mission compliance verification key hash mismatch." };
  }
  if (
    options.circuitDigest &&
    artifact.circuitDigest !== String(options.circuitDigest)
  ) {
    return { valid: false, reason: "Mission compliance circuit digest mismatch." };
  }

  const ProofClass =
    options.proofClass ??
    (await import("../../dist-zkapp/MissionComplianceProgram.js"))
      .MissionComplianceProof;
  const decodedProof = await ProofClass.fromJSON(artifact.proof);
  const decodedStatement = missionComplianceStatement(
    decodedProof.publicInput
  );
  for (const field of PUBLIC_INPUT_FIELDS) {
    if (decodedStatement[field] !== artifact.publicStatement[field]) {
      return {
        valid: false,
        reason: `Serialized proof public input ${field} does not match named statement.`
      };
    }
  }
  const { verify } = await import("o1js");
  const valid = await verify(artifact.proof, verificationKey);
  return valid
    ? {
        valid: true,
        artifactHash,
        verificationKeyHash: artifact.verificationKeyHash,
        publicStatement: artifact.publicStatement
      }
    : { valid: false, reason: "Mission compliance proof verification failed." };
}

export function missionComplianceProofFields() {
  return [...PUBLIC_INPUT_FIELDS];
}
