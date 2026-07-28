import fs from "node:fs";
import path from "node:path";
import { hmacSha256Hex, id, sha256Hex } from "./digest.js";
import { signJws, verifyJws, jwks } from "./authority-keys.js";
import {
  requireConfiguredValue,
  isProductionProfile,
  isZekoSettlementProfile
} from "./runtime.js";
import { writeJsonAtomic } from "./storage.js";
import {
  verifyEnterpriseIdentityAttestation
} from "./identity-attestations.js";
import { usdToMicrousd } from "./zeko-encoding.js";
import { validateArtifactSchema } from "./schema-validation.js";

const agents = new Map();
const missions = new Map();
const approvals = new Map();
const enforcementLog = [];
const replayCache = new Set();
const checkpointProgress = new Map();
const spendLedger = new Map();
const CHECKPOINT_ORDER = [
  "before_payment_offer",
  "before_private_compute",
  "before_external_side_effect",
  "after_receipt"
];
let loadedStatePath = null;

function missionSecret() {
  return requireConfiguredValue("MISSION_AUTHORITY_SECRET", "local-mission-authority-secret", "mission HMAC compatibility signatures");
}

function missionCompatibilitySignature(body) {
  if (isProductionProfile() && !process.env.MISSION_AUTHORITY_SECRET) return null;
  return hmacSha256Hex(missionSecret(), body);
}

function durableStateEnabled() {
  return isProductionProfile() || Boolean(process.env.MISSION_STATE_PATH);
}

function missionStatePath() {
  return process.env.MISSION_STATE_PATH ?? path.join(process.cwd(), "data", "mission-auth-state.json");
}

function mapFromEntries(map, entries = []) {
  map.clear();
  for (const [key, value] of entries) map.set(key, value);
}

function ensureStateLoaded() {
  const key = durableStateEnabled() ? missionStatePath() : "memory";
  if (loadedStatePath === key) return;
  loadedStatePath = key;
  if (!durableStateEnabled()) return;
  if (!fs.existsSync(key)) return;

  const state = JSON.parse(fs.readFileSync(key, "utf8"));
  mapFromEntries(agents, state.agents);
  mapFromEntries(missions, state.missions);
  mapFromEntries(approvals, state.approvals);
  enforcementLog.splice(0, enforcementLog.length, ...(state.enforcementLog ?? []));
  replayCache.clear();
  for (const value of state.replayCache ?? []) replayCache.add(value);
  mapFromEntries(checkpointProgress, state.checkpointProgress);
  mapFromEntries(spendLedger, state.spendLedger);
}

function persistState() {
  if (!durableStateEnabled()) return;
  const file = missionStatePath();
  const state = {
    version: "mission-auth-state-v1",
    savedAt: new Date().toISOString(),
    agents: Array.from(agents.entries()),
    missions: Array.from(missions.entries()),
    approvals: Array.from(approvals.entries()),
    enforcementLog,
    replayCache: Array.from(replayCache.values()),
    checkpointProgress: Array.from(checkpointProgress.entries()),
    spendLedger: Array.from(spendLedger.entries())
  };
  writeJsonAtomic(file, state);
}

export function buildAgentPassport(input = {}) {
  ensureStateLoaded();
  const identity = input.identityAttestation
    ? verifyEnterpriseIdentityAttestation(input.identityAttestation)
    : null;
  if (identity && !identity.valid) {
    throw new Error(identity.reason);
  }
  if (isProductionProfile() && !identity?.valid) {
    throw new Error("verified_enterprise_identity_attestation_required");
  }
  const agentId =
    identity?.agentId ??
    input.agentId ??
    "agent-research-ops-001";
  if (input.agentId && identity?.agentId && input.agentId !== identity.agentId) {
    throw new Error("agent_id_does_not_match_identity_attestation");
  }
  const domain = input.domain ?? "agents.local";
  if (
    isProductionProfile() &&
    !input.holderKeyCommitment
  ) {
    throw new Error("holder_key_commitment_required");
  }
  if (
    isZekoSettlementProfile() &&
    (!input.zekoHolderPublicKey || !input.zekoHolderKeyCommitment)
  ) {
    throw new Error("zeko_holder_key_binding_required");
  }
  const passport = {
    version: "agent-passport-v1",
    agentId,
    agentIdentifier: `aauth:${agentId}@${domain}`,
    represents: {
      type: "organization",
      id: identity?.organization ?? input.organization ?? "Northstar Bio"
    },
    vouchedBy: [
      {
        type: "enterprise-idp",
        protocol: input.idpProtocol ?? "saml-or-oidc",
        issuer:
          identity?.source?.issuer ??
          input.issuer ??
          "zk-oauth-demo.enterprise.example",
        attestationHash:
          input.identityAttestation?.attestationHash ?? null
      },
      {
        type: "mission-authority",
        issuer: "agent-mission-bound-auth"
      }
    ],
    keyBinding: {
      method: input.zekoHolderPublicKey
        ? "ed25519-and-zeko-pallas-v1"
        : "ed25519-v1",
      jwksUri: input.jwksUri ?? `https://${domain}/.well-known/agent-jwks.json`,
      holderKeyCommitment: input.holderKeyCommitment ?? null,
      zekoHolderPublicKey: input.zekoHolderPublicKey ?? null,
      zekoHolderKeyCommitment: input.zekoHolderKeyCommitment ?? null
    },
    authCommitment: input.identityAttestation?.authCommitment ?? null,
    identityAttestationHash:
      input.identityAttestation?.attestationHash ?? null,
    createdAt: new Date().toISOString()
  };

  const registered = {
    ...passport,
    passportId: id("agent", passport),
    passportCommitment: sha256Hex(passport),
    authoritySignature: missionCompatibilitySignature(passport),
    authorityJws: signJws(passport, { typ: "agent-passport+jwt" })
  };
  agents.set(registered.agentId, registered);
  persistState();
  return registered;
}

export function getAgentPassport(agentId) {
  ensureStateLoaded();
  return agents.get(agentId) ?? buildAgentPassport({ agentId });
}

export function findAgentPassport(agentId) {
  ensureStateLoaded();
  return agents.get(agentId) ?? null;
}

export function proposeMission(input) {
  ensureStateLoaded();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + (input.ttlMs ?? 20 * 60 * 1000));
  const agent = getAgentPassport(input.agentId);
  const mission = {
    version: "mission-bound-agent-auth-v1",
    agentId: agent.agentId,
    agentIdentifier: agent.agentIdentifier,
    personOrOrg: agent.represents,
    title: input.title ?? `Compute over ${input.datasetId}`,
    task: input.task,
    datasetId: input.datasetId,
    operation: input.operation,
    holderKeyCommitment:
      agent.keyBinding?.holderKeyCommitment ?? null,
    zekoHolderKeyCommitment:
      agent.keyBinding?.zekoHolderKeyCommitment ?? null,
    allowedDomains: input.allowedDomains ?? [],
    allowedTools: input.allowedTools ?? ["private_compute.run", "x402.payment_offer", "x402.pay", "x402.settle", "zeko.receipt.anchor"],
    allowedScopes: input.allowedScopes ?? [],
    constraints: {
      rawDataEgress: false,
      aggregateOnly: true,
      maxSpendUsd: input.maxSpendUsd ?? "5.00",
      allowedRails: input.allowedRails ?? ["zeko", "ethereum", "base"],
      requiresIndependentReceipt: true
    },
    checkpoints: [
      "before_payment_offer",
      "before_private_compute",
      "before_external_side_effect",
      "after_receipt"
    ],
    createdAt: now.toISOString(),
    expiresAt: expiresAt.toISOString()
  };
  const missionId = id("mission", mission);
  const missionHash = sha256Hex(mission);
  const record = {
    ...mission,
    missionId,
    missionHash,
    status: "proposed"
  };
  missions.set(missionId, record);
  persistState();
  return record;
}

export function approveMission(input) {
  ensureStateLoaded();
  const mission = missions.get(input.missionId);
  if (!mission) {
    throw new Error("mission_not_found");
  }
  const approverIdentity = input.approverAttestation
    ? verifyEnterpriseIdentityAttestation(input.approverAttestation)
    : null;
  if (approverIdentity && !approverIdentity.valid) {
    throw new Error(approverIdentity.reason);
  }
  if (isProductionProfile() && !approverIdentity?.valid) {
    throw new Error("verified_approver_identity_attestation_required");
  }

  const approvalBody = {
    version: "mission-approval-v1",
    missionId: mission.missionId,
    missionHash: mission.missionHash,
    approver: {
      type: input.approverType ?? "enterprise-human-or-policy",
      id: approverIdentity?.agentId ?? input.approverId ?? "approver@example.com",
      organization:
        approverIdentity?.organization ?? input.approverOrganization ?? null,
      issuer:
        approverIdentity?.source?.issuer ??
        input.issuer ??
        "agent-mission-bound-auth",
      identityAttestationHash:
        input.approverAttestation?.attestationHash ?? null
    },
    approvedTools: mission.allowedTools,
    approvedScopes: mission.allowedScopes,
    approvedRails: mission.constraints.allowedRails,
    approvedDomains: mission.allowedDomains,
    holderKeyCommitment: mission.holderKeyCommitment,
    zekoHolderKeyCommitment: mission.zekoHolderKeyCommitment,
    missionSnapshot: {
      agentId: mission.agentId,
      holderKeyCommitment: mission.holderKeyCommitment,
      zekoHolderKeyCommitment: mission.zekoHolderKeyCommitment,
      datasetId: mission.datasetId,
      operation: mission.operation,
      allowedDomains: mission.allowedDomains,
      constraints: mission.constraints,
      checkpoints: mission.checkpoints
    },
    expiresAt: mission.expiresAt,
    approvedAt: new Date().toISOString()
  };
  const approval = {
    ...approvalBody,
    approvalId: id("approval", approvalBody),
    approvalHash: sha256Hex(approvalBody),
    authoritySignature: missionCompatibilitySignature(approvalBody),
    authorityJws: signJws(approvalBody, { typ: "mission-approval+jwt" }),
    ...(isZekoSettlementProfile()
      ? {
          zekoAnchor: {
            primitive: "mission-approval-commitment-v1",
            commitment: sha256Hex({
              missionHash: mission.missionHash,
              approvalHash: sha256Hex(approvalBody)
            }),
            status: "ready-to-anchor"
          }
        }
      : {})
  };

  approvals.set(approval.approvalId, approval);
  missions.set(mission.missionId, { ...mission, status: "approved", approvalId: approval.approvalId });
  persistState();
  return approval;
}

export function verifyMissionApproval(approval, context) {
  ensureStateLoaded();
  if (!approval || typeof approval !== "object") {
    return { ok: false, reason: "Missing mission approval." };
  }
  const schema = validateArtifactSchema("approval", approval);
  if (!schema.valid) {
    return { ok: false, reason: schema.reason, schemaErrors: schema.errors };
  }
  const {
    approvalId,
    approvalHash,
    authoritySignature,
    authorityJws,
    zekoAnchor: _zekoAnchor,
    ...body
  } = approval;
  const bodyHash = sha256Hex(body);
  if (approvalId !== id("approval", body)) {
    return { ok: false, reason: "Mission approval id does not match approval body." };
  }
  if (approvalHash !== bodyHash) {
    return { ok: false, reason: "Mission approval hash does not match approval body." };
  }
  if (authorityJws) {
    try {
      const verified = verifyJws(authorityJws, jwks(), { typ: "mission-approval+jwt" });
      if (sha256Hex(verified.payload) !== bodyHash) {
        return { ok: false, reason: "Mission approval JWS payload does not match approval body." };
      }
    } catch (error) {
      return { ok: false, reason: error instanceof Error ? error.message : "Mission approval JWS is invalid." };
    }
  } else {
    if (isProductionProfile()) {
      return { ok: false, reason: "Mission approval JWS is required in production profile." };
    }
    const expectedSignature = hmacSha256Hex(missionSecret(), body);
    if (authoritySignature !== expectedSignature) {
      return { ok: false, reason: "Mission approval signature is invalid." };
    }
  }
  const approvalExpiry = Date.parse(approval.expiresAt);
  if (Number.isNaN(approvalExpiry) || approvalExpiry <= Date.now()) {
    return { ok: false, reason: "Mission approval is expired." };
  }
  const mission = missions.get(approval.missionId) ?? approval.missionSnapshot;
  if (!mission) {
    return { ok: false, reason: "Mission approval does not include a verifiable mission snapshot." };
  }

  if (context.agentId && context.agentId !== mission.agentId) {
    return { ok: false, reason: "Mission approval is not bound to this agent." };
  }
  if (context.datasetId && context.datasetId !== mission.datasetId) {
    return { ok: false, reason: "Mission approval is not bound to this dataset." };
  }
  if (context.operation && context.operation !== mission.operation) {
    return { ok: false, reason: "Mission approval is not bound to this operation." };
  }
  const targetDomain =
    context.targetDomain ?? context.domain ?? context.toDomain;
  if (
    targetDomain &&
    !(approval.approvedDomains ?? []).includes(targetDomain)
  ) {
    return {
      ok: false,
      reason: `Mission approval does not allow domain:${targetDomain}.`
    };
  }
  if (context.railId && !approval.approvedRails.includes(context.railId)) {
    return { ok: false, reason: `Mission approval does not allow rail:${context.railId}.` };
  }
  if (context.action && !approval.approvedTools.includes(context.action)) {
    return { ok: false, reason: `Mission approval does not allow action:${context.action}.` };
  }
  if (context.scope && !approval.approvedScopes.includes(context.scope)) {
    return { ok: false, reason: `Mission approval does not allow scope:${context.scope}.` };
  }

  return {
    ok: true,
    mission,
    approval,
    missionCommitment: sha256Hex({
      missionHash: body.missionHash,
      approvalHash: bodyHash
    })
  };
}

function maxSpendMicrousd(approval) {
  const value = approval.missionSnapshot?.constraints?.maxSpendUsd;
  try {
    return usdToMicrousd(value ?? "0");
  } catch {
    return null;
  }
}

function spendAmountMicrousd(context = {}) {
  try {
    return usdToMicrousd(context.spendUsd ?? context.amountUsd ?? "0");
  } catch {
    return null;
  }
}

function enforceReplayAndBudget({ approval, checkpoint, context = {} }) {
  const approvalId = approval.approvalId;
  const executionId = context.missionExecutionId ?? context.executionId;
  const highValueCheckpoint = checkpoint === "before_external_side_effect" || checkpoint === "before_private_compute";
  if (isProductionProfile() && !executionId) {
    return { ok: false, reason: "missionExecutionId is required in production profile." };
  }

  const idempotencyKey = context.idempotencyKey ?? context.paymentId ?? context.sideEffectId;
  if (isProductionProfile() && highValueCheckpoint && !idempotencyKey) {
    return { ok: false, reason: "idempotencyKey, paymentId, or sideEffectId is required for production side-effect checkpoints." };
  }
  if (idempotencyKey) {
    const replayKey = `${approvalId}:${checkpoint}:${idempotencyKey}`;
    if (replayCache.has(replayKey)) {
      return { ok: false, reason: `Replay detected for checkpoint:${checkpoint}.` };
    }
    replayCache.add(replayKey);
  }

  if ((isProductionProfile() || context.enforceCheckpointOrder) && executionId) {
    const orderIndex = CHECKPOINT_ORDER.indexOf(checkpoint);
    const progressKey = `${approvalId}:${executionId}`;
    const previous = checkpointProgress.get(progressKey) ?? -1;
    if (orderIndex >= 0 && orderIndex < previous) {
      return { ok: false, reason: `Checkpoint order regression from ${CHECKPOINT_ORDER[previous]} to ${checkpoint}.` };
    }
    if (orderIndex >= 0) checkpointProgress.set(progressKey, orderIndex);
  }

  const amount = spendAmountMicrousd(context);
  const max = maxSpendMicrousd(approval);
  if (amount === null || max === null) {
    return { ok: false, reason: "Mission budget contains an invalid decimal amount." };
  }
  if (amount > 0n) {
    const spent = BigInt(spendLedger.get(approvalId) ?? "0");
    if (max > 0n && spent + amount > max) {
      return { ok: false, reason: `Mission budget exceeded: ${spent + amount} microusd > ${max} microusd.` };
    }
    spendLedger.set(approvalId, (spent + amount).toString());
  }

  return { ok: true };
}

function failedCheckpointEvent(input, reason) {
  return {
    checkpointId: id("checkpoint", {
      checkpoint: input.checkpoint,
      at: Date.now(),
      missionId: input.approval?.missionId,
      context: input.context
    }),
    checkpoint: input.checkpoint,
    ok: false,
    reason,
    missionId: input.approval?.missionId ?? null,
    context: input.context,
    observedAt: new Date().toISOString()
  };
}

function successfulCheckpointEvent(input, verified) {
  return {
    checkpointId: id("checkpoint", {
      checkpoint: input.checkpoint,
      at: Date.now(),
      missionId: input.approval?.missionId,
      context: input.context
    }),
    checkpoint: input.checkpoint,
    ok: verified.ok,
    reason: verified.reason ?? null,
    missionId: input.approval?.missionId ?? null,
    context: input.context,
    observedAt: new Date().toISOString()
  };
}

function enforcementReceipt(input, event, verified) {
  return {
    primitive: "mission-checkpoint-receipt-v1",
    checkpoint: input.checkpoint,
    missionId: verified.mission.missionId,
    approvalId: verified.approval.approvalId,
    actionHash: sha256Hex(input.context),
    receiptHash: sha256Hex(event)
  };
}

export function verifyCheckpoint(input) {
  if (!input.approval?.missionSnapshot?.checkpoints?.includes(input.checkpoint)) {
    const reason = `Mission approval does not allow checkpoint:${input.checkpoint}.`;
    return {
      ok: false,
      reason,
      event: failedCheckpointEvent(input, reason)
    };
  }
  const verified = verifyMissionApproval(input.approval, input.context);
  const event = successfulCheckpointEvent(input, verified);
  if (!verified.ok) {
    return { ...verified, event };
  }
  return {
    ok: true,
    event,
    mission: verified.mission,
    approval: verified.approval,
    missionCommitment: verified.missionCommitment,
    enforcementReceipt: enforcementReceipt(input, event, verified)
  };
}

export function enforceCheckpoint(input) {
  const checked = verifyCheckpoint(input);
  if (!checked.ok) {
    enforcementLog.push(checked.event);
    persistState();
    return checked;
  }
  const replayBudget = enforceReplayAndBudget({
    approval: checked.approval,
    checkpoint: input.checkpoint,
    context: input.context
  });
  if (!replayBudget.ok) {
    const failedEvent = {
      ...checked.event,
      ok: false,
      reason: replayBudget.reason
    };
    enforcementLog.push(failedEvent);
    persistState();
    return { ok: false, reason: replayBudget.reason, event: failedEvent };
  }
  enforcementLog.push(checked.event);
  persistState();

  return checked;
}

export function listMissions() {
  ensureStateLoaded();
  return Array.from(missions.values());
}

export function listEnforcementLog() {
  ensureStateLoaded();
  return [...enforcementLog];
}

export function getMission(missionId) {
  ensureStateLoaded();
  return missions.get(missionId) ?? null;
}

export function getApproval(approvalId) {
  ensureStateLoaded();
  return approvals.get(approvalId) ?? null;
}
