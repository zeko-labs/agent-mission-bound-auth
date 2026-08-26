import { sha256Hex } from "./digest.js";
import { RAILS } from "./rails.js";
import { zekoSepoliaConfig } from "./zeko-network.js";

export function buildZekoContractPlan() {
  const zekoRail = RAILS.zeko;
  const network = zekoSepoliaConfig(process.env);
  const plan = {
    version: "mba-mission-registry-plan-v1",
    contract: {
      name: "MissionRegistry",
      source: "zkapp/MissionRegistry.ts",
      complianceProgram: "zkapp/MissionComplianceProgram.ts",
      networkId: network.networkId,
      networkName: network.networkName,
      signingNetworkId: network.signingNetworkId,
      nativeAsset: network.nativeAsset,
      graphql: zekoRail.extensions?.zeko?.graphql,
      archive: zekoRail.extensions?.zeko?.archive
    },
    state: {
      authorityKey: "PublicKey",
      protocolFeeRecipient: "PublicKey",
      registryRoot: "Field",
      sequence: "UInt64"
    },
    registryNamespaces: [
      "approval",
      "revocation",
      "nullifier",
      "receipt",
      "escrow"
    ],
    methods: [
      "configure(MissionRegistryConfig)",
      "anchorApproval(capabilityCommitment, approvalCommitment, authoritySignature, witness)",
      "revokeCapability(capabilityCommitment, authoritySignature, witness)",
      "fundMission(escrow, witness)",
      "settleMission(complianceProof, escrow, approvalWitness, revocationWitness, nullifierWitness, receiptWitness, escrowWitness)",
      "refundMission(escrow, witness)"
    ],
    settlementGuarantees: [
      "mission-compliance proof verifies",
      "approval is present",
      "capability is not revoked",
      "nullifier is unused",
      "receipt is inserted once",
      "escrow terms match proof statement",
      "beneficiary payout and protocol fee split are atomic"
    ],
    x402Linkage: {
      x402Version: 2,
      requestHeader: "PAYMENT-SIGNATURE",
      settlementModel: zekoRail.settlementModel,
      beneficiaryAddress:
        zekoRail.extensions?.zeko?.beneficiaryAddress,
      publicStatementFields: [
        "authCommitment",
        "capabilityCommitment",
        "policyCommitment",
        "approvalCommitment",
        "datasetCommitment",
        "domainProofCommitment",
        "outputCommitment",
        "paymentContextDigest",
        "receiptCommitment",
        "nullifier",
        "beneficiary",
        "payoutNanomina",
        "protocolFeeNanomina",
        "payoutNativeUnits",
        "protocolFeeNativeUnits"
      ]
    }
  };
  return { ...plan, planDigest: sha256Hex(plan) };
}
