import { id, sha256Hex } from "./digest.js";
import { verifyTraceChain } from "./boundary-events.js";
import { verifyReceipt } from "./receipts.js";
import { verifyAnchorPayload } from "./registry.js";

export const BROWSER_MISSION_PROFILE_VERSION = "mba-browser-mission-profile-v1";
export const REDACTED_TRACE_EXPORT_VERSION = "mba-redacted-trace-v1";
export const HANDOFF_RECEIPT_VERSION = "mba-human-handoff-v1";
export const EXECUTION_BUNDLE_VERSION = "mba-execution-bundle-v1";

export const BROWSER_MISSION_ACTIONS = Object.freeze([
  "browser.open",
  "page.read",
  "form.fill",
  "cart.prepare",
  "shipping.prepare",
  "delivery_option.select",
  "payment.prepare",
  "payment.authorize",
  "checkout.review",
  "final_submit"
]);

export const BROWSER_PAGE_STATE_CLASSES = Object.freeze([
  "unknown",
  "public_content",
  "authenticated_content",
  "form_entry",
  "cart",
  "shipping",
  "payment_selection",
  "final_review",
  "confirmation",
  "blocked"
]);

export const BROWSER_STOP_REASONS = Object.freeze([
  "none",
  "login_required",
  "payment_required",
  "final_approval_required",
  "policy_conflict",
  "budget_exceeded",
  "uncertain",
  "holder_key_missing",
  "capability_expired",
  "mission_capability_expired",
  "domain_not_allowed",
  "action_not_allowed"
]);

export const CHECKOUT_CHECKPOINTS = Object.freeze([
  "cart",
  "shipping",
  "delivery_option",
  "payment_selection",
  "final_review",
  "final_submit"
]);

const REDACTED_TRACE_ALLOWED_EVENT_KEYS = new Set([
  "eventId",
  "eventHash",
  "eventType",
  "action",
  "actionHash",
  "targetDomainHash",
  "resourceHash",
  "paymentContextDigest",
  "previousEventHash",
  "observedAt",
  "holderKeyThumbprint"
]);

const RAW_TRACE_FIELD_DENYLIST = new Set([
  "url",
  "currentUrl",
  "targetDomain",
  "resource",
  "selector",
  "input",
  "text",
  "html",
  "address",
  "email",
  "card",
  "cardLabel",
  "raw"
]);

function hashInput(raw, existingHash, fallback) {
  if (existingHash) return existingHash;
  if (raw === undefined || raw === null) return sha256Hex(fallback);
  return sha256Hex(raw);
}

function validCanonicalValue(value, allowed, label) {
  if (value === undefined || value === null) return { valid: true };
  if (!allowed.includes(value)) {
    return { valid: false, reason: `Unsupported ${label}: ${value}.` };
  }
  return { valid: true };
}

function scoreValid(score) {
  return typeof score === "number" && Number.isFinite(score) && score >= 0 && score <= 1;
}

export function buildBrowserMissionProfile(input = {}) {
  const body = {
    version: BROWSER_MISSION_PROFILE_VERSION,
    missionIdHash: input.missionIdHash,
    capabilityHash: input.capabilityHash,
    policyHash: input.policyHash,
    runnerType: input.runnerType ?? "local-runner",
    runtimeId: input.runtimeId,
    extensionIdHash: hashInput(input.extensionId, input.extensionIdHash, "no-extension-id"),
    holderKeyCommitment: input.holderKeyCommitment,
    sessionCommitment: hashInput(input.sessionId, input.sessionCommitment, "unknown-session"),
    tabCommitment: hashInput(input.tabId, input.tabCommitment, "unknown-tab"),
    currentUrlHash: hashInput(input.currentUrl, input.currentUrlHash, "unknown-url"),
    currentDomainHash: hashInput(input.currentDomain, input.currentDomainHash, "unknown-domain"),
    pageStateClass: input.pageStateClass ?? "unknown",
    safeNextActionScore: input.safeNextActionScore ?? 0,
    recommendedAction: input.recommendedAction ?? null,
    stopReason: input.stopReason ?? "none",
    checkoutCheckpoint: input.checkoutCheckpoint ?? null,
    allowedActionHashes: input.allowedActionHashes ?? (input.allowedActions ?? []).map((action) => sha256Hex(action)),
    allowedDomainHashes: input.allowedDomainHashes ?? (input.allowedDomains ?? []).map((domain) => sha256Hex(domain)),
    requiredCheckpoints: input.requiredCheckpoints ?? [],
    privacyProfile: input.privacyProfile ?? "public-hashes-only",
    createdAt: input.createdAt ?? new Date().toISOString()
  };
  return {
    ...body,
    profileId: input.profileId ?? id("browser_profile", body),
    profileHash: sha256Hex(body)
  };
}

export function verifyBrowserMissionProfile(profile, options = {}) {
  if (!profile || typeof profile !== "object") {
    return { valid: false, reason: "Missing browser mission profile." };
  }
  if (profile.version !== BROWSER_MISSION_PROFILE_VERSION) {
    return { valid: false, reason: "Unsupported browser mission profile version." };
  }
  const { profileId, profileHash, ...body } = profile;
  if (profileId !== id("browser_profile", body)) {
    return { valid: false, reason: "Browser mission profile id mismatch." };
  }
  if (profileHash !== sha256Hex(body)) {
    return { valid: false, reason: "Browser mission profile hash mismatch." };
  }
  for (const [key, expected] of [
    ["missionIdHash", options.missionIdHash],
    ["capabilityHash", options.capabilityHash],
    ["policyHash", options.policyHash],
    ["holderKeyCommitment", options.holderKeyCommitment]
  ]) {
    if (expected && profile[key] !== expected) {
      return { valid: false, reason: `Browser mission profile ${key} mismatch.` };
    }
  }
  const pageState = validCanonicalValue(profile.pageStateClass, BROWSER_PAGE_STATE_CLASSES, "browser page state");
  if (!pageState.valid) return pageState;
  const stopReason = validCanonicalValue(profile.stopReason, BROWSER_STOP_REASONS, "browser stop reason");
  if (!stopReason.valid) return stopReason;
  const checkoutCheckpoint = validCanonicalValue(profile.checkoutCheckpoint, CHECKOUT_CHECKPOINTS, "checkout checkpoint");
  if (!checkoutCheckpoint.valid) return checkoutCheckpoint;
  if (profile.recommendedAction) {
    const action = validCanonicalValue(profile.recommendedAction, BROWSER_MISSION_ACTIONS, "browser recommended action");
    if (!action.valid) return action;
  }
  if (!scoreValid(profile.safeNextActionScore)) {
    return { valid: false, reason: "Browser safeNextActionScore must be between 0 and 1." };
  }
  if (options.requireDomainHash && !profile.currentDomainHash) {
    return { valid: false, reason: "Browser mission profile requires currentDomainHash." };
  }
  if (options.requireTabCommitment && !profile.tabCommitment) {
    return { valid: false, reason: "Browser mission profile requires tabCommitment." };
  }
  return { valid: true, profileId, profileHash };
}

export function buildRedactedTraceExport(input = {}) {
  const events = input.events ?? input.traceEvents ?? [];
  const trace = input.trace ?? verifyTraceChain(events, {
    allowExpired: true,
    ...(input.traceOptions ?? {})
  });
  if (!trace.valid) {
    throw new Error(trace.reason);
  }
  const publicEvents = events.map((event) => ({
    eventId: event.eventId,
    eventHash: event.eventHash,
    eventType: event.eventType,
    action: event.action,
    actionHash: event.actionHash,
    targetDomainHash: event.targetDomainHash,
    resourceHash: event.resourceHash,
    paymentContextDigest: event.paymentContextDigest,
    previousEventHash: event.previousEventHash,
    observedAt: event.observedAt,
    holderKeyThumbprint: event.holderProof?.keyThumbprint ?? event.holderKeyCommitment
  }));
  const body = {
    version: REDACTED_TRACE_EXPORT_VERSION,
    missionIdHash: input.missionIdHash,
    capabilityHash: input.capabilityHash,
    policyHash: input.policyHash,
    eventCount: trace.eventCount,
    traceHash: trace.traceHash,
    latestEventHash: trace.latestEventHash,
    publicEvents,
    ownerTraceCommitment: input.ownerTraceCommitment ?? (input.ownerTrace ? sha256Hex(input.ownerTrace) : null),
    privacyProfile: input.privacyProfile ?? "public-hashes-only",
    exportedAt: input.exportedAt ?? new Date().toISOString()
  };
  return {
    ...body,
    redactedTraceId: input.redactedTraceId ?? id("redacted_trace", body),
    redactedTraceHash: sha256Hex(body)
  };
}

export function verifyRedactedTraceExport(traceExport, options = {}) {
  if (!traceExport || typeof traceExport !== "object") {
    return { valid: false, reason: "Missing redacted trace export." };
  }
  if (traceExport.version !== REDACTED_TRACE_EXPORT_VERSION) {
    return { valid: false, reason: "Unsupported redacted trace export version." };
  }
  const { redactedTraceId, redactedTraceHash, ...body } = traceExport;
  if (redactedTraceId !== id("redacted_trace", body)) {
    return { valid: false, reason: "Redacted trace id mismatch." };
  }
  if (redactedTraceHash !== sha256Hex(body)) {
    return { valid: false, reason: "Redacted trace hash mismatch." };
  }
  if (!Array.isArray(traceExport.publicEvents)) {
    return { valid: false, reason: "Redacted trace publicEvents must be an array." };
  }
  for (const event of traceExport.publicEvents) {
    for (const key of Object.keys(event)) {
      if (!REDACTED_TRACE_ALLOWED_EVENT_KEYS.has(key) || RAW_TRACE_FIELD_DENYLIST.has(key)) {
        return { valid: false, reason: `Redacted trace leaks non-public field: ${key}.` };
      }
    }
  }
  for (const [key, expected] of [
    ["missionIdHash", options.missionIdHash],
    ["capabilityHash", options.capabilityHash],
    ["policyHash", options.policyHash]
  ]) {
    if (expected && traceExport[key] !== expected) {
      return { valid: false, reason: `Redacted trace ${key} mismatch.` };
    }
  }
  return {
    valid: true,
    redactedTraceId,
    redactedTraceHash,
    traceHash: traceExport.traceHash,
    eventCount: traceExport.eventCount
  };
}

export function buildHandoffReceipt(input = {}) {
  const body = {
    version: HANDOFF_RECEIPT_VERSION,
    missionIdHash: input.missionIdHash,
    capabilityHash: input.capabilityHash,
    policyHash: input.policyHash,
    stopReason: input.stopReason,
    checkpoint: input.checkpoint ?? null,
    action: input.action ?? null,
    targetDomainHash: hashInput(input.targetDomain, input.targetDomainHash, "unknown-domain"),
    eventHash: input.eventHash ?? null,
    traceHash: input.traceHash ?? null,
    paymentContextDigest: input.paymentContextDigest ?? null,
    holderKeyThumbprint: input.holderKeyThumbprint ?? null,
    humanApprovalRequired: input.humanApprovalRequired ?? true,
    notesHash: input.notesHash ?? (input.notes ? sha256Hex(input.notes) : null),
    occurredAt: input.occurredAt ?? new Date().toISOString()
  };
  return {
    ...body,
    handoffId: input.handoffId ?? id("handoff", body),
    handoffHash: sha256Hex(body)
  };
}

export function verifyHandoffReceipt(handoff, options = {}) {
  if (!handoff || typeof handoff !== "object") {
    return { valid: false, reason: "Missing handoff receipt." };
  }
  if (handoff.version !== HANDOFF_RECEIPT_VERSION) {
    return { valid: false, reason: "Unsupported handoff receipt version." };
  }
  const { handoffId, handoffHash, ...body } = handoff;
  if (handoffId !== id("handoff", body)) {
    return { valid: false, reason: "Handoff receipt id mismatch." };
  }
  if (handoffHash !== sha256Hex(body)) {
    return { valid: false, reason: "Handoff receipt hash mismatch." };
  }
  const stopReason = validCanonicalValue(handoff.stopReason, BROWSER_STOP_REASONS, "handoff stop reason");
  if (!stopReason.valid) return stopReason;
  if (handoff.stopReason === "none") {
    return { valid: false, reason: "Handoff receipt requires a stop reason." };
  }
  for (const [key, expected] of [
    ["missionIdHash", options.missionIdHash],
    ["capabilityHash", options.capabilityHash],
    ["policyHash", options.policyHash]
  ]) {
    if (expected && handoff[key] !== expected) {
      return { valid: false, reason: `Handoff receipt ${key} mismatch.` };
    }
  }
  return { valid: true, handoffId, handoffHash, stopReason: handoff.stopReason };
}

export function buildExecutionBundle(input = {}) {
  const ownerTrace = input.ownerTraceUrl || input.ownerTraceCommitment
    ? {
        access: input.ownerTraceAccess ?? "owner-only",
        urlHash: input.ownerTraceUrl ? sha256Hex(input.ownerTraceUrl) : null,
        commitment: input.ownerTraceCommitment ?? null
      }
    : null;
  const body = {
    version: EXECUTION_BUNDLE_VERSION,
    exportedAt: input.exportedAt ?? new Date().toISOString(),
    capability: input.capability ?? null,
    policy: input.policy ?? null,
    browserProfile: input.browserProfile ?? null,
    redactedTrace: input.redactedTrace ?? null,
    handoff: input.handoff ?? null,
    receipt: input.receipt ?? null,
    zekoAnchor: input.zekoAnchor ?? input.anchor ?? null,
    settlement: input.settlement ?? null,
    verifierLinks: input.verifierLinks ?? [],
    ownerTrace
  };
  return {
    ...body,
    bundleId: input.bundleId ?? id("execution_bundle", body),
    bundleHash: sha256Hex(body)
  };
}

export function verifyExecutionBundle(bundle, options = {}) {
  if (!bundle || typeof bundle !== "object") {
    return { valid: false, reason: "Missing execution bundle." };
  }
  if (bundle.version !== EXECUTION_BUNDLE_VERSION) {
    return { valid: false, reason: "Unsupported execution bundle version." };
  }
  const { bundleId, bundleHash, ...body } = bundle;
  if (bundleId !== id("execution_bundle", body)) {
    return { valid: false, reason: "Execution bundle id mismatch." };
  }
  if (bundleHash !== sha256Hex(body)) {
    return { valid: false, reason: "Execution bundle hash mismatch." };
  }
  if (bundle.browserProfile) {
    const profile = verifyBrowserMissionProfile(bundle.browserProfile, options);
    if (!profile.valid) return profile;
  }
  if (bundle.redactedTrace) {
    const trace = verifyRedactedTraceExport(bundle.redactedTrace, options);
    if (!trace.valid) return trace;
  }
  if (bundle.handoff) {
    const handoff = verifyHandoffReceipt(bundle.handoff, options);
    if (!handoff.valid) return handoff;
  }
  if (bundle.receipt) {
    const receipt = verifyReceipt(bundle.receipt, options);
    if (!receipt.valid) return receipt;
    if (bundle.zekoAnchor) {
      const anchor = verifyAnchorPayload(bundle.receipt, bundle.zekoAnchor);
      if (!anchor.valid) return anchor;
    }
  }
  return { valid: true, bundleId, bundleHash };
}
