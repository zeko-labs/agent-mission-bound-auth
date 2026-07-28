import { id, sha256Hex } from "./digest.js";
import { verifyTraceChain } from "./boundary-events.js";
import { isProductionStrictVerifier } from "./runtime.js";
import {
  MISSION_COMPLIANCE_PROOF_SYSTEM,
  verifyMissionComplianceProofArtifact
} from "./zeko-proof.js";
import { validateArtifactSchema } from "./schema-validation.js";
import { canonicalValueToField } from "./zeko-encoding.js";
import {
  validateZekoCapabilityBinding,
  verifyZekoDomainProofAttestation
} from "./zeko-inputs.js";
import { verifyCapability } from "./capabilities.js";

export const PRODUCTION_FINAL_SETTLEMENT_STATES = new Set([
  "settlement_release_allowed",
  "settled"
]);

export const RECEIPT_SETTLEMENT_STATES = new Set([
  "receipt_created",
  "proof_prepared",
  "proof_verified",
  "anchor_prepared",
  "anchored",
  "settlement_release_allowed",
  "settled",
  "disputed",
  "expired",
  "failed"
]);

function receiptIdentityBody(body) {
  const {
    anchor: _anchor,
    exportedAt: _exportedAt,
    registryRoot: _registryRoot,
    settlementState: _settlementState,
    ...identityBody
  } = body;
  return identityBody;
}

export function buildMissionReceiptExport(input = {}) {
  const trace = input.traceEvents
    ? verifyTraceChain(input.traceEvents, { allowExpired: true })
    : input.trace;
  if (!trace?.valid && input.traceEvents) {
    throw new Error(trace.reason);
  }

  const body = {
    schema: "mission-bound-auth-receipt-v1",
    mission: {
      missionIdHash: input.missionIdHash,
      capabilityHash: input.capabilityHash,
      authCommitment: input.authCommitment ?? null,
      approvalCommitment: input.approvalCommitment ?? null,
      issuer: input.issuer,
      audience: input.audience
    },
    capabilityArtifact: input.capabilityArtifact ?? input.capability ?? null,
    policy: {
      policyHash: input.policyHash,
      allowedDomainsHash: input.allowedDomainsHash,
      allowedActionsHash: input.allowedActionsHash,
      maxSpendCommitment: input.maxSpendCommitment,
      paymentRailsHash: input.paymentRailsHash
    },
    holder: {
      keyThumbprint: input.holderKeyThumbprint,
      proofScheme: input.proofScheme ?? "digest-holder-proof-v1"
    },
    trace: {
      eventCount: trace.eventCount,
      traceHash: trace.traceHash,
      latestEventHash: trace.latestEventHash
    },
    payment: {
      paymentCommitment: input.paymentCommitment,
      rail: input.rail,
      amountCommitment: input.amountCommitment,
      paymentContextDigest: input.paymentContextDigest
    },
    proof: {
      statementKind: input.statementKind ?? "mission-bound-trace-compliance-v1",
      statementHash: input.statementHash,
      proofSystem: input.proofSystem ?? "signed-commitment-transition",
      verificationKeyHash: input.verificationKeyHash ?? null,
      artifact: input.proofArtifact ?? null
    },
    domainProof: input.domainProof ?? null,
    zekoStatement: input.zekoStatement ?? null,
    nullifier: input.nullifier,
    registryRoot: input.registryRoot ?? null,
    settlementState: input.settlementState ?? "receipt_created",
    anchor: input.anchor ?? null,
    exportedAt: input.exportedAt ?? new Date().toISOString()
  };
  const receiptId = input.receiptId ?? id("receipt", receiptIdentityBody(body));
  return {
    ...body,
    receiptId,
    receiptHash: sha256Hex(body)
  };
}

export function verifyReceipt(receipt, options = {}) {
  if (!receipt || typeof receipt !== "object") {
    return { valid: false, reason: "Missing receipt." };
  }
  const schema = validateArtifactSchema("receipt", receipt);
  if (!schema.valid) return schema;
  if (receipt.schema !== "mission-bound-auth-receipt-v1") {
    return { valid: false, reason: "Unsupported receipt schema." };
  }
  const { receiptId, receiptHash, ...body } = receipt;
  if (receiptId !== id("receipt", receiptIdentityBody(body))) {
    return { valid: false, reason: "Receipt id mismatch." };
  }
  if (receiptHash !== sha256Hex(body)) {
    return { valid: false, reason: "Receipt hash mismatch." };
  }
  if (!receipt.mission?.capabilityHash) {
    return { valid: false, reason: "Receipt missing capabilityHash." };
  }
  if (!receipt.policy?.policyHash) {
    return { valid: false, reason: "Receipt missing policyHash." };
  }
  if (!receipt.trace?.traceHash || !receipt.trace?.latestEventHash) {
    return { valid: false, reason: "Receipt missing trace commitment." };
  }
  if (!receipt.payment?.paymentContextDigest) {
    return { valid: false, reason: "Receipt missing paymentContextDigest." };
  }
  if (!receipt.nullifier) {
    return { valid: false, reason: "Receipt missing nullifier." };
  }
  if (!RECEIPT_SETTLEMENT_STATES.has(receipt.settlementState)) {
    return { valid: false, reason: "Receipt has unsupported settlementState." };
  }
  if (
    !options.allowAnchorPrepared &&
    PRODUCTION_FINAL_SETTLEMENT_STATES.has(receipt.settlementState) &&
    !receipt.anchor
  ) {
    return { valid: false, reason: "Production-final receipts require anchor evidence." };
  }
  if (isProductionStrictVerifier(options, options.env ?? process.env)) {
    if (receipt.holder?.proofScheme !== "ed25519-holder-proof-v1") {
      return { valid: false, reason: "production_strict receipts require ed25519-holder-proof-v1 or stronger holder proof." };
    }
    if (!receipt.proof?.statementHash || !receipt.proof?.proofSystem) {
      return { valid: false, reason: "production_strict receipts require proof statement evidence." };
    }
    if (
      receipt.proof.proofSystem !== MISSION_COMPLIANCE_PROOF_SYSTEM ||
      !receipt.proof.artifact
    ) {
      return { valid: false, reason: "production_strict receipts require a concrete Zeko mission compliance proof artifact." };
    }
    if (!receipt.zekoStatement) {
      return { valid: false, reason: "production_strict receipts require the proof-bound Zeko public statement." };
    }
    if (!receipt.capabilityArtifact) {
      return { valid: false, reason: "production_strict receipts require the signed capability artifact." };
    }
    if (!receipt.domainProof) {
      return { valid: false, reason: "production_strict receipts require domain proof evidence." };
    }
    if (!receipt.anchor) {
      return { valid: false, reason: "production_strict receipts require Zeko anchor evidence." };
    }
  }
  return {
    valid: true,
    receiptId,
    receiptHash,
    nullifier: receipt.nullifier,
    settlementState: receipt.settlementState
  };
}

export function verifyProductionStrictReceipt(receipt, options = {}) {
  return verifyReceipt(receipt, {
    ...options,
    verifierMode: "production_strict"
  });
}

export async function verifyProductionReceiptCryptographically(
  receipt,
  options = {}
) {
  const structural = verifyProductionStrictReceipt(receipt, options);
  if (!structural.valid) return structural;
  const proof = await verifyMissionComplianceProofArtifact(
    receipt.proof.artifact,
    {
      verificationKey: options.verificationKey,
      circuitDigest: options.circuitDigest,
      expectedStatement: receipt.zekoStatement
    }
  );
  if (!proof.valid) return proof;
  const capability = verifyReceiptCapabilityBinding(
    receipt,
    options
  );
  if (!capability.valid) return capability;
  if (
    receipt.proof.verificationKeyHash !==
    receipt.proof.artifact.verificationKeyHash
  ) {
    return { valid: false, reason: "Receipt verificationKeyHash does not match proof artifact." };
  }
  if (
    receipt.proof.statementHash !== sha256Hex(receipt.zekoStatement)
  ) {
    return { valid: false, reason: "Receipt statementHash does not bind the Zeko public statement." };
  }
  const domainProof = await verifyReceiptDomainProof(receipt, options);
  if (!domainProof.valid) return domainProof;
  return {
    ...structural,
    cryptographicProof: "valid",
    capabilityVerification: capability,
    domainProofVerification: domainProof,
    proofArtifactHash: proof.artifactHash,
    publicStatement: proof.publicStatement
  };
}

export function verifyReceiptCapabilityBinding(
  receipt,
  options = {}
) {
  if (!options.authorityJwks) {
    return {
      valid: false,
      reason: "Trusted mission authority JWKS is required."
    };
  }
  const artifact = receipt?.capabilityArtifact;
  const capability = verifyCapability(artifact, {
    jwks: options.authorityJwks,
    now: options.now
  });
  if (!capability.valid) return capability;
  const bindingCheck = validateZekoCapabilityBinding(
    artifact.zekoBinding,
    artifact
  );
  if (!bindingCheck.valid) return bindingCheck;
  const binding = artifact.zekoBinding;
  const statement = receipt.zekoStatement;
  const statementChecks = [
    ["missionIdHash", binding.missionIdHashField],
    ["authCommitment", binding.authCommitmentField],
    ["capabilityCommitment", binding.capabilityCommitment],
    ["policyCommitment", binding.policyCommitment],
    ["approvalCommitment", binding.approvalCommitment],
    ["holderKeyCommitment", binding.holderKeyCommitment],
    [
      "domainVerifierKeyCommitment",
      binding.domainVerifierKeyCommitment
    ],
    ["allowedActionsRoot", binding.allowedActionsRoot],
    ["allowedDomainsRoot", binding.allowedDomainsRoot],
    ["datasetCommitment", binding.datasetCommitment],
    ["nullifier", binding.nullifier],
    ["validUntilSlot", binding.validUntilSlot],
    ["maxSpendMicrousd", binding.maxSpendMicrousd],
    ["beneficiary", binding.beneficiary],
    ["payoutNanomina", binding.payoutNanomina],
    ["protocolFeeNanomina", binding.protocolFeeNanomina]
  ];
  for (const [field, expected] of statementChecks) {
    if (String(statement?.[field]) !== String(expected)) {
      return {
        valid: false,
        reason: `Signed capability Zeko binding ${field} mismatch.`
      };
    }
  }
  const receiptChecks = [
    [
      "mission.capabilityHash",
      receipt.mission?.capabilityHash,
      artifact.capabilityHash
    ],
    [
      "mission.authCommitment",
      receipt.mission?.authCommitment,
      artifact.authCommitment
    ],
    [
      "mission.approvalCommitment",
      receipt.mission?.approvalCommitment,
      binding.approvalCommitment
    ],
    [
      "policy.policyHash",
      receipt.policy?.policyHash,
      artifact.policyHash
    ],
    [
      "holder.keyThumbprint",
      receipt.holder?.keyThumbprint,
      artifact.holderKeyCommitment
    ],
    [
      "payment.paymentContextDigest",
      receipt.payment?.paymentContextDigest,
      statement.paymentContextDigest
    ],
    ["nullifier", receipt.nullifier, statement.nullifier]
  ];
  for (const [field, actual, expected] of receiptChecks) {
    if (String(actual) !== String(expected)) {
      return {
        valid: false,
        reason: `Receipt ${field} does not match the signed capability or proof.`
      };
    }
  }
  return {
    valid: true,
    capabilityId: artifact.capabilityId,
    capabilityHash: artifact.capabilityHash
  };
}

export async function verifyReceiptDomainProof(receipt, options = {}) {
  if (!receipt?.domainProof || !receipt?.zekoStatement) {
    return {
      valid: false,
      reason: "Domain proof evidence and a Zeko statement are required."
    };
  }
  const expectedCommitment =
    receipt.zekoStatement.domainProofCommitment;
  let actualCommitment;
  try {
    actualCommitment =
      canonicalValueToField(
        receipt.domainProof.evidence
      ).toString();
  } catch {
    return {
      valid: false,
      reason: "Domain proof evidence is not canonically encodable."
    };
  }
  if (actualCommitment !== String(expectedCommitment)) {
    return {
      valid: false,
      reason: "Domain proof evidence does not match domainProofCommitment."
    };
  }
  const attestation = verifyZekoDomainProofAttestation(
    receipt.domainProof,
    receipt.zekoStatement
  );
  if (!attestation.valid) return attestation;
  if (typeof options.domainProofVerifier !== "function") {
    return {
      valid: false,
      reason: "A trusted domainProofVerifier is required for production settlement."
    };
  }
  try {
    const result = await options.domainProofVerifier(
      receipt.domainProof.evidence,
      {
        receipt,
        publicStatement: receipt.zekoStatement,
        expectedCommitment,
        ...(options.domainProofContext ?? {})
      }
    );
    if (result !== true && result?.valid !== true) {
      return {
        valid: false,
        reason:
          result?.reason ??
          "Domain proof verifier rejected the evidence."
      };
    }
    return {
      valid: true,
      commitment: actualCommitment,
      attestation,
      verifierResult: result
    };
  } catch (error) {
    return {
      valid: false,
      reason:
        error instanceof Error
          ? `Domain proof verification failed: ${error.message}`
          : "Domain proof verification failed."
    };
  }
}
