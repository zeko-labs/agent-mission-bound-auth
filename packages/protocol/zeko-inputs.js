import {
  Bool,
  Field,
  MerkleMap,
  Poseidon,
  PrivateKey,
  PublicKey,
  Signature,
  UInt32,
  UInt64
} from "o1js";

import {
  buildStringSetMap,
  canonicalValueToField,
  digestHexToField,
  nativeToNanoUnits,
  stringSetKey,
  usdToMicrousd
} from "./zeko-encoding.js";
import {
  ZEKO_GRAPHQL_NETWORK_ID,
  ZEKO_NATIVE_ASSET,
  ZEKO_NETWORK_NAME,
  ZEKO_PROTOCOL_NETWORK_ID,
  ZEKO_SIGNING_NETWORK_ID
} from "./zeko-network.js";

export const ZEKO_CAPABILITY_BINDING_VERSION =
  "mba-zeko-capability-binding-v3";
export const LEGACY_ZEKO_CAPABILITY_BINDING_VERSION =
  "mba-zeko-capability-binding-v2";
export const ZEKO_ACTION_NAMESPACE = "mba-boundary-action-v1";
export const ZEKO_DOMAIN_NAMESPACE = "mba-boundary-domain-v1";

function field(value, label) {
  try {
    return Field.from(value);
  } catch {
    throw new TypeError(`${label} must be an o1js Field value.`);
  }
}

function nonzeroField(value, label) {
  const parsed = field(value, label);
  if (parsed.equals(Field(0)).toBoolean()) {
    throw new TypeError(`${label} must be nonzero.`);
  }
  return parsed;
}

function uint32(value, label) {
  try {
    return UInt32.from(value);
  } catch {
    throw new TypeError(`${label} must be an unsigned 32-bit integer.`);
  }
}

function uint64(value, label) {
  try {
    return UInt64.from(value);
  } catch {
    throw new TypeError(`${label} must be an unsigned 64-bit integer.`);
  }
}

function digestField(value, label) {
  try {
    return digestHexToField(value);
  } catch {
    throw new TypeError(`${label} must be a 32-byte hexadecimal digest.`);
  }
}

function privateKey(value, label) {
  if (value instanceof PrivateKey) return value;
  try {
    return PrivateKey.fromBase58(value);
  } catch {
    throw new TypeError(`${label} must be a Pallas private key.`);
  }
}

function publicKey(value, label) {
  if (value instanceof PublicKey) return value;
  try {
    return PublicKey.fromBase58(value);
  } catch {
    throw new TypeError(`${label} must be a Pallas public key.`);
  }
}

function signature(value, label) {
  if (value instanceof Signature) return value;
  try {
    return Signature.fromBase58(value);
  } catch {
    throw new TypeError(`${label} must be a Pallas signature.`);
  }
}

function randomNonzeroField() {
  let value = Field.random();
  while (value.equals(Field(0)).toBoolean()) value = Field.random();
  return value;
}

function privateField(value, label) {
  return value === undefined
    ? randomNonzeroField()
    : nonzeroField(value, label);
}

function atomicAmount(input, atomicKey, decimalKey, parser, label) {
  if (input[atomicKey] !== undefined) {
    return uint64(input[atomicKey], label);
  }
  if (input[decimalKey] === undefined) {
    throw new TypeError(`${decimalKey} or ${atomicKey} is required.`);
  }
  return uint64(parser(input[decimalKey]), label);
}

function exactFieldString(value) {
  return field(value, "field").toString();
}

function assertEqual(actual, expected, label) {
  if (String(actual) !== String(expected)) {
    throw new Error(`${label} mismatch.`);
  }
}

function assertStringArray(value, label) {
  if (!Array.isArray(value) || value.some((entry) => typeof entry !== "string" || !entry)) {
    throw new TypeError(`${label} must contain non-empty strings.`);
  }
}

function deriveArtifactField(value, explicitValue, label) {
  if (explicitValue !== undefined) {
    return nonzeroField(explicitValue, label);
  }
  if (typeof value === "string" && /^[0-9a-f]{64}$/i.test(value)) {
    return digestField(value, label);
  }
  if (value === undefined || value === null) {
    throw new TypeError(`${label} is required.`);
  }
  return canonicalValueToField(value);
}

async function missionProgramTypes() {
  return import("../../dist-zkapp/MissionComplianceProgram.js");
}

export function zekoHolderKeyCommitment(holderPublicKey) {
  const key = publicKey(holderPublicKey, "holderPublicKey");
  return Poseidon.hash(key.toFields()).toString();
}

export function domainProofAttestationMessageFromStatement(statement) {
  return Poseidon.hash([
    field(statement.missionIdHash, "missionIdHash"),
    field(statement.capabilityCommitment, "capabilityCommitment"),
    field(statement.policyCommitment, "policyCommitment"),
    field(statement.datasetCommitment, "datasetCommitment"),
    field(statement.domainProofCommitment, "domainProofCommitment"),
    field(statement.outputCommitment, "outputCommitment")
  ]);
}

export function verifyZekoDomainProofAttestation(
  domainProof,
  statement
) {
  try {
    if (
      domainProof?.attestation?.scheme !==
      "pallas-domain-proof-attestation-v1"
    ) {
      throw new Error("Unsupported domain proof attestation scheme.");
    }
    const verifierKey = publicKey(
      domainProof.attestation.publicKey,
      "domainProof.attestation.publicKey"
    );
    assertEqual(
      Poseidon.hash(verifierKey.toFields()).toString(),
      statement.domainVerifierKeyCommitment,
      "Domain verifier key commitment"
    );
    const verifierSignature = signature(
      domainProof.attestation.signature,
      "domainProof.attestation.signature"
    );
    if (
      !verifierSignature
        .verify(verifierKey, [
          domainProofAttestationMessageFromStatement(statement)
        ])
        .toBoolean()
    ) {
      throw new Error("Domain proof verifier signature is invalid.");
    }
    return {
      valid: true,
      verifierPublicKey: verifierKey.toBase58()
    };
  } catch (error) {
    return {
      valid: false,
      reason:
        error instanceof Error
          ? error.message
          : "Invalid domain proof attestation."
    };
  }
}

export function validateZekoCapabilityBinding(binding, context = {}) {
  if (!binding || typeof binding !== "object") {
    return { valid: false, reason: "Missing Zeko capability binding." };
  }
  try {
    const legacyBinding =
      binding.version === LEGACY_ZEKO_CAPABILITY_BINDING_VERSION;
    if (
      binding.version !== ZEKO_CAPABILITY_BINDING_VERSION &&
      !legacyBinding
    ) {
      throw new Error("Unsupported Zeko capability binding version.");
    }
    if (legacyBinding) {
      if (
        binding.protocolNetworkId !== undefined ||
        binding.graphqlNetworkId !== undefined
      ) {
        throw new Error(
          "Legacy Zeko capability bindings cannot declare v3 network identifiers."
        );
      }
      if (binding.network !== ZEKO_GRAPHQL_NETWORK_ID) {
        throw new Error(
          `Legacy Zeko capability binding network must be ${ZEKO_GRAPHQL_NETWORK_ID}.`
        );
      }
    } else {
      if (
        binding.network !== ZEKO_PROTOCOL_NETWORK_ID ||
        binding.protocolNetworkId !== ZEKO_PROTOCOL_NETWORK_ID
      ) {
        throw new Error(
          `Zeko protocol network must be ${ZEKO_PROTOCOL_NETWORK_ID}.`
        );
      }
      if (binding.graphqlNetworkId !== ZEKO_GRAPHQL_NETWORK_ID) {
        throw new Error(
          `Zeko GraphQL network must be ${ZEKO_GRAPHQL_NETWORK_ID}.`
        );
      }
    }
    if (binding.signingNetworkId !== ZEKO_SIGNING_NETWORK_ID) {
      throw new Error(
        `Zeko signing network must be ${ZEKO_SIGNING_NETWORK_ID}.`
      );
    }
    if (
      binding.nativeAsset?.symbol !== ZEKO_NATIVE_ASSET.symbol ||
      binding.nativeAsset?.decimals !== ZEKO_NATIVE_ASSET.decimals ||
      binding.nativeAsset?.standard !== ZEKO_NATIVE_ASSET.standard ||
      binding.nativeAsset?.tokenId !== ZEKO_NATIVE_ASSET.tokenId
    ) {
      throw new Error("Zeko capability binding must use native sETH.");
    }
    const holder = publicKey(binding.holderPublicKey, "holderPublicKey");
    assertEqual(
      binding.holderKeyCommitment,
      Poseidon.hash(holder.toFields()).toString(),
      "Zeko holder key commitment"
    );
    const domainVerifier = publicKey(
      binding.domainVerifierPublicKey,
      "domainVerifierPublicKey"
    );
    assertEqual(
      binding.domainVerifierKeyCommitment,
      Poseidon.hash(domainVerifier.toFields()).toString(),
      "Zeko domain verifier key commitment"
    );

    const actionValues =
      context.allowedActions ?? binding.allowedActions ?? [];
    const domainValues =
      context.allowedDomains ?? binding.allowedDomains ?? [];
    assertStringArray(actionValues, "allowedActions");
    assertStringArray(domainValues, "allowedDomains");
    assertEqual(
      binding.allowedActionsRoot,
      buildStringSetMap(ZEKO_ACTION_NAMESPACE, actionValues).root.toString(),
      "Zeko allowed-actions root"
    );
    assertEqual(
      binding.allowedDomainsRoot,
      buildStringSetMap(ZEKO_DOMAIN_NAMESPACE, domainValues).root.toString(),
      "Zeko allowed-domains root"
    );

    const missionIdHash = context.missionIdHash ?? binding.missionIdHash;
    const authCommitment = context.authCommitment ?? binding.authCommitment;
    assertEqual(
      binding.missionIdHashField,
      digestField(missionIdHash, "missionIdHash").toString(),
      "Zeko mission id field"
    );
    assertEqual(
      binding.authCommitmentField,
      digestField(authCommitment, "authCommitment").toString(),
      "Zeko auth commitment field"
    );

    const expectedSpend =
      context.maxSpendUsd === undefined
        ? binding.maxSpendMicrousd
        : usdToMicrousd(context.maxSpendUsd).toString();
    assertEqual(
      binding.maxSpendMicrousd,
      expectedSpend,
      "Zeko maximum spend"
    );

    for (const name of [
      "missionIdHashField",
      "authCommitmentField",
      "holderKeyCommitment",
      "domainVerifierKeyCommitment",
      "allowedActionsRoot",
      "allowedDomainsRoot",
      "datasetCommitment",
      "policyCommitment",
      "capabilityCommitment",
      "approvalCommitment",
      "nullifier"
    ]) {
      nonzeroField(binding[name], `zekoBinding.${name}`);
    }
    uint32(binding.validUntilSlot, "zekoBinding.validUntilSlot");
    uint64(binding.maxSpendMicrousd, "zekoBinding.maxSpendMicrousd");
    const payout = uint64(binding.payoutNanomina, "zekoBinding.payoutNanomina");
    const fee = uint64(
      binding.protocolFeeNanomina,
      "zekoBinding.protocolFeeNanomina"
    );
    if (payout.equals(UInt64.zero).toBoolean()) {
      throw new Error("Zeko payout must be nonzero.");
    }
    if (fee.equals(UInt64.zero).toBoolean()) {
      throw new Error("Zeko protocol fee must be nonzero.");
    }
    assertEqual(
      binding.payoutNativeUnits,
      binding.payoutNanomina,
      "Zeko native payout"
    );
    assertEqual(
      binding.protocolFeeNativeUnits,
      binding.protocolFeeNanomina,
      "Zeko native protocol fee"
    );
    publicKey(binding.beneficiary, "zekoBinding.beneficiary");

    const expectedApproval = Poseidon.hash([
      field(binding.authCommitmentField, "authCommitmentField"),
      field(binding.capabilityCommitment, "capabilityCommitment"),
      field(binding.policyCommitment, "policyCommitment"),
      uint32(binding.validUntilSlot, "validUntilSlot").value
    ]);
    assertEqual(
      binding.approvalCommitment,
      expectedApproval.toString(),
      "Zeko approval commitment"
    );
    if (
      context.zekoHolderPublicKey &&
      context.zekoHolderPublicKey !== binding.holderPublicKey
    ) {
      throw new Error("Zeko holder public key does not match the passport.");
    }
    if (
      context.zekoHolderKeyCommitment &&
      context.zekoHolderKeyCommitment !== binding.holderKeyCommitment
    ) {
      throw new Error("Zeko holder commitment does not match the passport.");
    }
    return { valid: true, binding };
  } catch (error) {
    return {
      valid: false,
      reason:
        error instanceof Error
          ? error.message
          : "Invalid Zeko capability binding."
    };
  }
}

export async function prepareMissionComplianceBinding(input = {}) {
  assertStringArray(input.allowedActions, "allowedActions");
  assertStringArray(input.allowedDomains, "allowedDomains");
  const {
    MissionCompliancePublicInput,
    missionApprovalCommitment,
    missionCapabilityCommitment,
    missionPolicyCommitment
  } = await missionProgramTypes();

  const holderKey = privateKey(
    input.holderPrivateKey,
    "holderPrivateKey"
  );
  const holderPublicKey = holderKey.toPublicKey();
  const beneficiary = publicKey(input.beneficiary, "beneficiary");
  const domainVerifierPublicKey = publicKey(
    input.domainVerifierPublicKey,
    "domainVerifierPublicKey"
  );
  const missionIdHash = digestField(input.missionIdHash, "missionIdHash");
  const authCommitment = digestField(
    input.authCommitment,
    "authCommitment"
  );
  const principalCommitment = deriveArtifactField(
    input.principalHash,
    input.principalCommitment,
    "principalCommitment"
  );
  const agentCommitment = deriveArtifactField(
    input.agentId,
    input.agentCommitment,
    "agentCommitment"
  );
  const datasetCommitment = deriveArtifactField(
    input.datasetCommitment ??
      {
        datasetId: input.datasetId,
        dataScopes: input.dataScopes ?? []
      },
    input.datasetCommitmentField,
    "datasetCommitment"
  );
  const allowedActions = buildStringSetMap(
    ZEKO_ACTION_NAMESPACE,
    input.allowedActions
  );
  const allowedDomains = buildStringSetMap(
    ZEKO_DOMAIN_NAMESPACE,
    input.allowedDomains
  );
  const validUntilSlot = uint32(input.validUntilSlot, "validUntilSlot");
  const maxSpendMicrousd = atomicAmount(
    input,
    "maxSpendMicrousd",
    "maxSpendUsd",
    usdToMicrousd,
    "maxSpendMicrousd"
  );
  const payoutNanomina = atomicAmount(
    {
      payoutNativeUnits:
        input.payoutNativeUnits ?? input.payoutNanomina,
      payoutNative: input.payoutNative ?? input.payoutMina
    },
    "payoutNativeUnits",
    "payoutNative",
    nativeToNanoUnits,
    "payoutNativeUnits"
  );
  const protocolFeeNanomina = atomicAmount(
    {
      protocolFeeNativeUnits:
        input.protocolFeeNativeUnits ?? input.protocolFeeNanomina,
      protocolFeeNative:
        input.protocolFeeNative ?? input.protocolFeeMina
    },
    "protocolFeeNativeUnits",
    "protocolFeeNative",
    nativeToNanoUnits,
    "protocolFeeNativeUnits"
  );
  const secrets = {
    principalCommitment,
    agentCommitment,
    capabilityNonce: privateField(
      input.capabilityNonce,
      "capabilityNonce"
    ),
    policyNonce: privateField(input.policyNonce, "policyNonce"),
    nullifierSecret: privateField(
      input.nullifierSecret,
      "nullifierSecret"
    ),
    receiptNonce: privateField(input.receiptNonce, "receiptNonce"),
    holderPrivateKey: holderKey
  };

  const publicInput = new MissionCompliancePublicInput({
    missionIdHash,
    authCommitment,
    capabilityCommitment: Field(0),
    policyCommitment: Field(0),
    approvalCommitment: Field(0),
    holderKeyCommitment: Poseidon.hash(holderPublicKey.toFields()),
    domainVerifierKeyCommitment: Poseidon.hash(
      domainVerifierPublicKey.toFields()
    ),
    allowedActionsRoot: allowedActions.root,
    allowedDomainsRoot: allowedDomains.root,
    datasetCommitment,
    domainProofCommitment: Field(1),
    outputCommitment: Field(1),
    paymentContextDigest: Field(0),
    traceRoot: Field(0),
    receiptCommitment: Field(0),
    nullifier: Field(0),
    validUntilSlot,
    lastObservedSlot: UInt32.zero,
    maxSpendMicrousd,
    totalSpendMicrousd: UInt64.zero,
    eventCount: UInt32.zero,
    beneficiary,
    payoutNanomina,
    protocolFeeNanomina
  });
  publicInput.policyCommitment = missionPolicyCommitment(
    publicInput,
    secrets.policyNonce
  );
  publicInput.capabilityCommitment = missionCapabilityCommitment(
    publicInput,
    secrets.principalCommitment,
    secrets.agentCommitment,
    secrets.capabilityNonce
  );
  publicInput.approvalCommitment =
    missionApprovalCommitment(publicInput);
  publicInput.nullifier = Poseidon.hash([
    publicInput.capabilityCommitment,
    publicInput.missionIdHash,
    secrets.nullifierSecret
  ]);

  const binding = {
    version: ZEKO_CAPABILITY_BINDING_VERSION,
    network: ZEKO_PROTOCOL_NETWORK_ID,
    protocolNetworkId: ZEKO_PROTOCOL_NETWORK_ID,
    graphqlNetworkId: ZEKO_GRAPHQL_NETWORK_ID,
    networkName: ZEKO_NETWORK_NAME,
    signingNetworkId: ZEKO_SIGNING_NETWORK_ID,
    nativeAsset: ZEKO_NATIVE_ASSET,
    missionIdHash: input.missionIdHash,
    authCommitment: input.authCommitment,
    missionIdHashField: publicInput.missionIdHash.toString(),
    authCommitmentField: publicInput.authCommitment.toString(),
    holderPublicKey: holderPublicKey.toBase58(),
    holderKeyCommitment: publicInput.holderKeyCommitment.toString(),
    domainVerifierPublicKey: domainVerifierPublicKey.toBase58(),
    domainVerifierKeyCommitment:
      publicInput.domainVerifierKeyCommitment.toString(),
    allowedActions: allowedActions.values,
    allowedDomains: allowedDomains.values,
    allowedActionsRoot: publicInput.allowedActionsRoot.toString(),
    allowedDomainsRoot: publicInput.allowedDomainsRoot.toString(),
    datasetCommitment: publicInput.datasetCommitment.toString(),
    policyCommitment: publicInput.policyCommitment.toString(),
    capabilityCommitment: publicInput.capabilityCommitment.toString(),
    approvalCommitment: publicInput.approvalCommitment.toString(),
    nullifier: publicInput.nullifier.toString(),
    validUntilSlot: publicInput.validUntilSlot.toString(),
    maxSpendMicrousd: publicInput.maxSpendMicrousd.toString(),
    beneficiary: publicInput.beneficiary.toBase58(),
    payoutNanomina: publicInput.payoutNanomina.toString(),
    protocolFeeNanomina: publicInput.protocolFeeNanomina.toString(),
    payoutNativeUnits: publicInput.payoutNanomina.toString(),
    protocolFeeNativeUnits: publicInput.protocolFeeNanomina.toString()
  };
  const validation = validateZekoCapabilityBinding(binding, {
    missionIdHash: input.missionIdHash,
    authCommitment: input.authCommitment,
    allowedActions: input.allowedActions,
    allowedDomains: input.allowedDomains,
    maxSpendUsd: input.maxSpendUsd
  });
  if (!validation.valid) throw new Error(validation.reason);

  return {
    binding,
    privateWitnessMaterial: secrets
  };
}

export async function buildMissionComplianceInputs(input = {}) {
  const capability = input.capability;
  const binding = capability?.zekoBinding ?? input.zekoBinding;
  const validation = validateZekoCapabilityBinding(binding, {
    missionIdHash: capability?.missionIdHash,
    authCommitment: capability?.authCommitment,
    allowedActions: capability?.allowedActions,
    allowedDomains: capability?.allowedDomains,
    maxSpendUsd: capability?.maxSpendUsd
  });
  if (!validation.valid) throw new Error(validation.reason);

  const material = input.privateWitnessMaterial;
  if (!material) {
    throw new TypeError("privateWitnessMaterial is required.");
  }
  const holderKey = privateKey(
    material.holderPrivateKey,
    "privateWitnessMaterial.holderPrivateKey"
  );
  assertEqual(
    holderKey.toPublicKey().toBase58(),
    binding.holderPublicKey,
    "Zeko holder private key"
  );

  const {
    MAX_MISSION_EVENTS,
    MissionBoundaryEventWitness,
    MissionCompliancePublicInput,
    MissionComplianceWitness,
    missionBoundaryEventHash,
    missionReceiptCommitment
  } = await missionProgramTypes();
  const actionMap = buildStringSetMap(
    ZEKO_ACTION_NAMESPACE,
    binding.allowedActions
  ).map;
  const domainMap = buildStringSetMap(
    ZEKO_DOMAIN_NAMESPACE,
    binding.allowedDomains
  ).map;
  const runtimeEvents = input.events ?? [];
  if (runtimeEvents.length === 0 || runtimeEvents.length > MAX_MISSION_EVENTS) {
    throw new RangeError(
      `events must contain between 1 and ${MAX_MISSION_EVENTS} entries.`
    );
  }

  const domainProofEvidence = input.domainProof?.evidence;
  if (domainProofEvidence === undefined) {
    throw new TypeError("domainProof.evidence is required.");
  }
  const domainProofCommitment = deriveArtifactField(
    domainProofEvidence,
    input.domainProofCommitment,
    "domainProofCommitment"
  );
  const outputCommitment = deriveArtifactField(
    input.output,
    input.outputCommitment,
    "outputCommitment"
  );
  let publicInput = new MissionCompliancePublicInput({
    missionIdHash: field(binding.missionIdHashField, "missionIdHashField"),
    authCommitment: field(binding.authCommitmentField, "authCommitmentField"),
    capabilityCommitment: field(
      binding.capabilityCommitment,
      "capabilityCommitment"
    ),
    policyCommitment: field(binding.policyCommitment, "policyCommitment"),
    approvalCommitment: field(
      binding.approvalCommitment,
      "approvalCommitment"
    ),
    holderKeyCommitment: field(
      binding.holderKeyCommitment,
      "holderKeyCommitment"
    ),
    domainVerifierKeyCommitment: field(
      binding.domainVerifierKeyCommitment,
      "domainVerifierKeyCommitment"
    ),
    allowedActionsRoot: field(
      binding.allowedActionsRoot,
      "allowedActionsRoot"
    ),
    allowedDomainsRoot: field(
      binding.allowedDomainsRoot,
      "allowedDomainsRoot"
    ),
    datasetCommitment: field(
      binding.datasetCommitment,
      "datasetCommitment"
    ),
    domainProofCommitment,
    outputCommitment,
    paymentContextDigest: Field(0),
    traceRoot: Field(0),
    receiptCommitment: Field(0),
    nullifier: field(binding.nullifier, "nullifier"),
    validUntilSlot: uint32(binding.validUntilSlot, "validUntilSlot"),
    lastObservedSlot: UInt32.zero,
    maxSpendMicrousd: uint64(
      binding.maxSpendMicrousd,
      "maxSpendMicrousd"
    ),
    totalSpendMicrousd: UInt64.zero,
    eventCount: UInt32.from(runtimeEvents.length),
    beneficiary: publicKey(binding.beneficiary, "beneficiary"),
    payoutNanomina: uint64(binding.payoutNanomina, "payoutNanomina"),
    protocolFeeNanomina: uint64(
      binding.protocolFeeNanomina,
      "protocolFeeNanomina"
    )
  });
  const domainProofAttestation = verifyZekoDomainProofAttestation(
    input.domainProof,
    {
      missionIdHash: publicInput.missionIdHash.toString(),
      capabilityCommitment:
        publicInput.capabilityCommitment.toString(),
      policyCommitment: publicInput.policyCommitment.toString(),
      datasetCommitment: publicInput.datasetCommitment.toString(),
      domainProofCommitment:
        publicInput.domainProofCommitment.toString(),
      outputCommitment: publicInput.outputCommitment.toString(),
      domainVerifierKeyCommitment:
        publicInput.domainVerifierKeyCommitment.toString()
    }
  );
  if (!domainProofAttestation.valid) {
    throw new Error(domainProofAttestation.reason);
  }

  const events = [];
  let previousEventHash = Field(0);
  let traceRoot = Field(0);
  let totalSpend = UInt64.zero;
  let previousSlot = UInt32.zero;
  for (const [index, runtimeEvent] of runtimeEvents.entries()) {
    if (!binding.allowedActions.includes(runtimeEvent.action)) {
      throw new Error(`Event ${index} action is outside the capability.`);
    }
    if (!binding.allowedDomains.includes(runtimeEvent.domain)) {
      throw new Error(`Event ${index} domain is outside the capability.`);
    }
    const observedSlot = uint32(
      runtimeEvent.observedSlot,
      `events[${index}].observedSlot`
    );
    if (
      index > 0 &&
      observedSlot.lessThan(previousSlot).toBoolean()
    ) {
      throw new Error("Boundary event slots must be monotonic.");
    }
    const actionKey = stringSetKey(
      ZEKO_ACTION_NAMESPACE,
      runtimeEvent.action
    );
    const domainKey = stringSetKey(
      ZEKO_DOMAIN_NAMESPACE,
      runtimeEvent.domain
    );
    const paymentContextDigest = deriveArtifactField(
      runtimeEvent.paymentContext,
      runtimeEvent.paymentContextDigest,
      `events[${index}].paymentContextDigest`
    );
    const unsigned = new MissionBoundaryEventWitness({
      enabled: Bool(true),
      actionKey,
      domainKey,
      resourceCommitment: deriveArtifactField(
        runtimeEvent.resource,
        runtimeEvent.resourceCommitment,
        `events[${index}].resourceCommitment`
      ),
      paymentContextDigest,
      spendMicrousd: atomicAmount(
        runtimeEvent,
        "spendMicrousd",
        "spendUsd",
        usdToMicrousd,
        `events[${index}].spendMicrousd`
      ),
      observedSlot,
      eventNonce: privateField(
        runtimeEvent.eventNonce,
        `events[${index}].eventNonce`
      ),
      holderSignature: Signature.create(holderKey, [Field(0)]),
      actionWitness: actionMap.getWitness(actionKey),
      domainWitness: domainMap.getWitness(domainKey)
    });
    const eventHash = missionBoundaryEventHash(
      publicInput,
      previousEventHash,
      unsigned
    );
    const event = new MissionBoundaryEventWitness({
      ...unsigned,
      holderSignature: Signature.create(holderKey, [eventHash])
    });
    events.push(event);
    previousEventHash = eventHash;
    traceRoot = Poseidon.hash([traceRoot, eventHash]);
    totalSpend = totalSpend.add(event.spendMicrousd);
    previousSlot = observedSlot;
    publicInput.paymentContextDigest = paymentContextDigest;
  }

  const dummyKey = PrivateKey.random();
  const emptyActionMap = new MerkleMap();
  const emptyDomainMap = new MerkleMap();
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
        actionWitness: emptyActionMap.getWitness(Field(0)),
        domainWitness: emptyDomainMap.getWitness(Field(0))
      })
    );
  }
  publicInput.traceRoot = traceRoot;
  publicInput.totalSpendMicrousd = totalSpend;
  publicInput.lastObservedSlot = previousSlot;
  publicInput.receiptCommitment = missionReceiptCommitment(
    publicInput,
    field(material.receiptNonce, "receiptNonce")
  );

  const witness = new MissionComplianceWitness({
    principalCommitment: field(
      material.principalCommitment,
      "principalCommitment"
    ),
    agentCommitment: field(material.agentCommitment, "agentCommitment"),
    capabilityNonce: field(material.capabilityNonce, "capabilityNonce"),
    policyNonce: field(material.policyNonce, "policyNonce"),
    nullifierSecret: field(
      material.nullifierSecret,
      "nullifierSecret"
    ),
    receiptNonce: field(material.receiptNonce, "receiptNonce"),
    holderPublicKey: holderKey.toPublicKey(),
    domainVerifierPublicKey: publicKey(
      input.domainProof.attestation.publicKey,
      "domainProof.attestation.publicKey"
    ),
    domainProofSignature: signature(
      input.domainProof.attestation.signature,
      "domainProof.attestation.signature"
    ),
    events
  });

  return {
    publicInput,
    witness,
    binding,
    receiptCommitment: publicInput.receiptCommitment.toString(),
    traceRoot: publicInput.traceRoot.toString(),
    paymentContextDigest: publicInput.paymentContextDigest.toString(),
    totalSpendMicrousd: publicInput.totalSpendMicrousd.toString()
  };
}

export async function createDomainProofAttestation(input = {}) {
  const verifierKey = privateKey(
    input.domainVerifierPrivateKey,
    "domainVerifierPrivateKey"
  );
  const binding = input.zekoBinding ?? input.capability?.zekoBinding;
  const bindingCheck = validateZekoCapabilityBinding(
    binding,
    input.capability ?? {}
  );
  if (!bindingCheck.valid) throw new Error(bindingCheck.reason);
  assertEqual(
    verifierKey.toPublicKey().toBase58(),
    binding.domainVerifierPublicKey,
    "Domain verifier private key"
  );
  const domainProofCommitment = deriveArtifactField(
    input.evidence,
    input.domainProofCommitment,
    "domainProofCommitment"
  );
  const outputCommitment = deriveArtifactField(
    input.output,
    input.outputCommitment,
    "outputCommitment"
  );
  const statement = {
    missionIdHash: binding.missionIdHashField,
    capabilityCommitment: binding.capabilityCommitment,
    policyCommitment: binding.policyCommitment,
    datasetCommitment: binding.datasetCommitment,
    domainProofCommitment: domainProofCommitment.toString(),
    outputCommitment: outputCommitment.toString(),
    domainVerifierKeyCommitment:
      binding.domainVerifierKeyCommitment
  };
  const verifierSignature = Signature.create(verifierKey, [
    domainProofAttestationMessageFromStatement(statement)
  ]);
  return {
    evidence: input.evidence,
    attestation: {
      scheme: "pallas-domain-proof-attestation-v1",
      publicKey: verifierKey.toPublicKey().toBase58(),
      signature: verifierSignature.toBase58()
    }
  };
}

export function normalizeZekoBindingFields(binding) {
  const normalized = { ...binding };
  for (const key of [
    "missionIdHashField",
    "authCommitmentField",
    "holderKeyCommitment",
    "domainVerifierKeyCommitment",
    "allowedActionsRoot",
    "allowedDomainsRoot",
    "datasetCommitment",
    "policyCommitment",
    "capabilityCommitment",
    "approvalCommitment",
    "nullifier"
  ]) {
    normalized[key] = exactFieldString(binding[key]);
  }
  return normalized;
}
