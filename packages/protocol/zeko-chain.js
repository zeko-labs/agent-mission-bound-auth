import { id, sha256Hex } from "./digest.js";
import { verifyMissionComplianceProofArtifact } from "./zeko-proof.js";
import { validateArtifactSchema } from "./schema-validation.js";
import {
  ZEKO_GRAPHQL_NETWORK_ID,
  ZEKO_NATIVE_ASSET,
  ZEKO_NETWORK_NAME,
  ZEKO_PROTOCOL_NETWORK_ID,
  ZEKO_SIGNING_NETWORK_ID
} from "./zeko-network.js";

export const ZEKO_REGISTRY_ANCHOR_VERSION =
  "mba-zeko-registry-anchor-v3";
export const LEGACY_ZEKO_REGISTRY_ANCHOR_VERSION =
  "mba-zeko-registry-anchor-v2";

function requiredString(value, label) {
  if (typeof value !== "string" || value.length === 0) {
    throw new TypeError(`${label} is required.`);
  }
  return value;
}

function graphqlEndpoint(value) {
  const endpoint = requiredString(value, "Zeko GraphQL endpoint");
  return endpoint.endsWith("/graphql")
    ? endpoint
    : `${endpoint.replace(/\/$/, "")}/graphql`;
}

async function queryGraphql(endpoint, query, variables) {
  const response = await fetch(graphqlEndpoint(endpoint), {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ query, variables })
  });
  const body = await response.json();
  if (!response.ok || body.errors?.length) {
    throw new Error(
      body.errors?.map((entry) => entry.message).join("; ") ??
      `Zeko GraphQL request failed with ${response.status}.`
    );
  }
  return body.data;
}

function normalizedTransactionStatus(value) {
  let status = value;
  if (typeof status === "string" && status.startsWith("[")) {
    try {
      const parsed = JSON.parse(status);
      status = Array.isArray(parsed) ? parsed[0] : parsed;
    } catch {
      // Preserve the raw status so an unrecognized gateway value fails closed.
    }
  }
  return String(status ?? "").toLowerCase();
}

export function buildZekoRegistryAnchor(input = {}) {
  const protocolNetworkId =
    input.protocolNetworkId ?? input.networkId ?? ZEKO_PROTOCOL_NETWORK_ID;
  const graphqlNetworkId =
    input.graphqlNetworkId ?? ZEKO_GRAPHQL_NETWORK_ID;
  const signingNetworkId =
    input.signingNetworkId ?? ZEKO_SIGNING_NETWORK_ID;
  if (
    protocolNetworkId !== ZEKO_PROTOCOL_NETWORK_ID ||
    graphqlNetworkId !== ZEKO_GRAPHQL_NETWORK_ID ||
    signingNetworkId !== ZEKO_SIGNING_NETWORK_ID
  ) {
    throw new Error("Zeko registry anchor network identifiers are invalid.");
  }
  const body = {
    version: ZEKO_REGISTRY_ANCHOR_VERSION,
    networkId: protocolNetworkId,
    protocolNetworkId,
    graphqlNetworkId,
    networkName: input.networkName ?? ZEKO_NETWORK_NAME,
    signingNetworkId,
    nativeAsset: input.nativeAsset ?? ZEKO_NATIVE_ASSET,
    registryAddress: requiredString(
      input.registryAddress,
      "registryAddress"
    ),
    transactionHash: requiredString(
      input.transactionHash ?? input.txHash,
      "transactionHash"
    ),
    sequence: String(input.sequence),
    registryRoot: requiredString(input.registryRoot, "registryRoot"),
    missionIdHash: requiredString(input.missionIdHash, "missionIdHash"),
    capabilityCommitment: requiredString(
      input.capabilityCommitment,
      "capabilityCommitment"
    ),
    approvalCommitment: requiredString(
      input.approvalCommitment,
      "approvalCommitment"
    ),
    receiptCommitment: requiredString(
      input.receiptCommitment,
      "receiptCommitment"
    ),
    nullifier: requiredString(input.nullifier, "nullifier"),
    paymentContextDigest: requiredString(
      input.paymentContextDigest,
      "paymentContextDigest"
    ),
    beneficiary: requiredString(input.beneficiary, "beneficiary"),
    payoutNanomina: String(input.payoutNanomina),
    protocolFeeNanomina: String(input.protocolFeeNanomina),
    payoutNativeUnits: String(
      input.payoutNativeUnits ?? input.payoutNanomina
    ),
    protocolFeeNativeUnits: String(
      input.protocolFeeNativeUnits ?? input.protocolFeeNanomina
    ),
    proofArtifactHash: requiredString(
      input.proofArtifactHash,
      "proofArtifactHash"
    ),
    blockHeight: input.blockHeight === undefined
      ? null
      : String(input.blockHeight),
    anchoredAt: input.anchoredAt ?? new Date().toISOString()
  };
  return {
    ...body,
    anchorId: id("zeko_anchor", body),
    anchorHash: sha256Hex(body)
  };
}

export function verifyZekoRegistryAnchorBinding(
  receipt,
  anchor,
  options = {}
) {
  if (!anchor || typeof anchor !== "object") {
    return { valid: false, reason: "Missing Zeko registry anchor." };
  }
  const schema = validateArtifactSchema("zeko-registry-anchor", anchor);
  if (!schema.valid) return schema;
  const legacyAnchor =
    anchor.version === LEGACY_ZEKO_REGISTRY_ANCHOR_VERSION;
  if (anchor.version !== ZEKO_REGISTRY_ANCHOR_VERSION && !legacyAnchor) {
    return { valid: false, reason: "Unsupported Zeko registry anchor." };
  }
  if (
    legacyAnchor
      ? anchor.networkId !== ZEKO_GRAPHQL_NETWORK_ID ||
        anchor.protocolNetworkId !== undefined ||
        anchor.graphqlNetworkId !== undefined
      : anchor.networkId !== ZEKO_PROTOCOL_NETWORK_ID ||
        anchor.protocolNetworkId !== ZEKO_PROTOCOL_NETWORK_ID ||
        anchor.graphqlNetworkId !== ZEKO_GRAPHQL_NETWORK_ID
  ) {
    return {
      valid: false,
      reason: "Zeko registry anchor network binding is invalid."
    };
  }
  const { anchorId, anchorHash, ...body } = anchor;
  if (
    anchorId !== id("zeko_anchor", body) ||
    anchorHash !== sha256Hex(body)
  ) {
    return { valid: false, reason: "Zeko registry anchor integrity check failed." };
  }
  const statement =
    options.publicStatement ??
    receipt?.zekoStatement ??
    receipt?.proof?.artifact?.publicStatement;
  if (!statement) {
    return { valid: false, reason: "Proof-bound Zeko public statement is required." };
  }
  const checks = [
    ["missionIdHash", statement.missionIdHash],
    ["capabilityCommitment", statement.capabilityCommitment],
    ["approvalCommitment", statement.approvalCommitment],
    ["receiptCommitment", statement.receiptCommitment],
    ["nullifier", statement.nullifier],
    ["paymentContextDigest", statement.paymentContextDigest],
    ["beneficiary", statement.beneficiary],
    ["payoutNanomina", statement.payoutNanomina],
    ["protocolFeeNanomina", statement.protocolFeeNanomina]
  ];
  for (const [field, expected] of checks) {
    if (String(anchor[field]) !== String(expected)) {
      return { valid: false, reason: `Zeko registry anchor ${field} mismatch.` };
    }
  }
  if (
    anchor.payoutNativeUnits !== anchor.payoutNanomina ||
    anchor.protocolFeeNativeUnits !== anchor.protocolFeeNanomina
  ) {
    return {
      valid: false,
      reason: "Zeko native-unit aliases do not match proof amounts."
    };
  }
  if (
    anchor.proofArtifactHash !== receipt?.proof?.artifact?.artifactHash
  ) {
    return { valid: false, reason: "Zeko anchor proofArtifactHash mismatch." };
  }
  return {
    valid: true,
    anchorId,
    anchorHash,
    registryRoot: anchor.registryRoot,
    sequence: anchor.sequence
  };
}

export async function fetchZekoRegistryState(input = {}) {
  const data = await queryGraphql(
    input.graphql,
    `query MbaRegistryState($publicKey: PublicKey!) {
      account(publicKey: $publicKey) {
        nonce
        inferredNonce
        zkappState
      }
    }`,
    { publicKey: requiredString(input.registryAddress, "registryAddress") }
  );
  if (!data.account?.zkappState) {
    throw new Error("MissionRegistry account or zkApp state was not found.");
  }
  const state = data.account.zkappState;
  if (state.length < 6) {
    throw new Error("MissionRegistry zkApp state has an unexpected layout.");
  }
  return {
    registryAddress: input.registryAddress,
    nonce: data.account.nonce,
    inferredNonce: data.account.inferredNonce,
    registryRoot: state[4],
    sequence: state[5],
    rawState: state
  };
}

export async function fetchZekoTransactionStatus(input = {}) {
  const data = await queryGraphql(
    input.graphql,
    `query MbaTransactionEvents($input: EventFilterOptionsInput!) {
      events(input: $input) {
        blockInfo {
          height
          chainStatus
        }
        eventData {
          transactionInfo {
            status
            hash
            sequenceNumber
          }
        }
      }
    }`,
    {
      input: {
        address: requiredString(
          input.registryAddress,
          "registryAddress"
        )
      }
    }
  );
  const transactionHash = requiredString(
    input.transactionHash,
    "transactionHash"
  );
  for (const block of data.events ?? []) {
    for (const event of block.eventData ?? []) {
      const transaction = event.transactionInfo;
      if (transaction?.hash !== transactionHash) continue;
      const status = normalizedTransactionStatus(transaction.status);
      const chainStatus = String(
        block.blockInfo?.chainStatus ?? ""
      ).toLowerCase();
      const applied = status === "applied";
      const canonical = chainStatus === "canonical";
      return {
        included: applied && canonical,
        applied,
        canonical,
        status,
        rawStatus: transaction.status,
        chainStatus,
        blockHeight: block.blockInfo?.height,
        sequenceNumber: transaction.sequenceNumber
      };
    }
  }
  return {
    included: false,
    applied: false,
    canonical: false,
    status: "not_found",
    chainStatus: null,
    blockHeight: null,
    sequenceNumber: null
  };
}

export function isZekoTransactionConfirmedForAnchor(
  transactionStatus,
  state,
  anchor
) {
  if (transactionStatus.included) return true;
  return transactionStatus.applied === true &&
    !transactionStatus.chainStatus &&
    state.sequence === anchor.sequence &&
    state.registryRoot === anchor.registryRoot;
}

export async function verifyZekoRegistryAnchorOnChain(
  receipt,
  anchor,
  options = {}
) {
  const binding = verifyZekoRegistryAnchorBinding(receipt, anchor, options);
  if (!binding.valid) return binding;
  if (!options.graphql) {
    return { valid: false, reason: "Zeko GraphQL endpoint is required." };
  }
  if (
    options.expectedRegistryAddress &&
    anchor.registryAddress !== options.expectedRegistryAddress
  ) {
    return { valid: false, reason: "Zeko registry address is not trusted." };
  }

  const proof = await verifyMissionComplianceProofArtifact(
    receipt.proof.artifact,
    {
      verificationKey: options.verificationKey,
      circuitDigest: options.circuitDigest,
      expectedStatement: receipt.zekoStatement
    }
  );
  if (!proof.valid) return proof;

  const [state, transactionStatus] = await Promise.all([
    fetchZekoRegistryState({
      graphql: options.graphql,
      registryAddress: anchor.registryAddress
    }),
    fetchZekoTransactionStatus({
      graphql: options.graphql,
      transactionHash: anchor.transactionHash,
      registryAddress: anchor.registryAddress
    })
  ]);
  if (!isZekoTransactionConfirmedForAnchor(
    transactionStatus,
    state,
    anchor
  )) {
    return {
      valid: false,
      reason:
        `Zeko transaction is ${transactionStatus.status ?? "unknown"} ` +
        `in ${transactionStatus.chainStatus ?? "unknown"} chain state, not canonically included.`
    };
  }
  if (
    BigInt(state.sequence) < BigInt(anchor.sequence)
  ) {
    return { valid: false, reason: "On-chain registry sequence predates anchor." };
  }
  if (
    state.sequence === anchor.sequence &&
    state.registryRoot !== anchor.registryRoot
  ) {
    return { valid: false, reason: "Current on-chain registry root does not match anchor." };
  }
  if (
    state.sequence !== anchor.sequence &&
    typeof options.historicalAnchorVerifier !== "function"
  ) {
    return {
      valid: false,
      reason: "Anchor is historical; an archive-backed historicalAnchorVerifier is required."
    };
  }
  if (state.sequence !== anchor.sequence) {
    const historical = await options.historicalAnchorVerifier({
      receipt,
      anchor,
      state
    });
    if (!historical?.valid) {
      return historical ?? {
        valid: false,
        reason: "Historical Zeko registry anchor was not verified."
      };
    }
  }
  return {
    valid: true,
    transactionStatus: transactionStatus.status,
    chainStatus: transactionStatus.chainStatus,
    blockHeight: transactionStatus.blockHeight,
    transactionHash: anchor.transactionHash,
    registryAddress: anchor.registryAddress,
    registryRoot: anchor.registryRoot,
    sequence: anchor.sequence,
    proofArtifactHash: proof.artifactHash
  };
}
