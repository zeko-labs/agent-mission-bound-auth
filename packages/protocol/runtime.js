import { timingSafeEqual } from "node:crypto";

export const MISSION_AUTH_PROFILES = Object.freeze([
  "demo",
  "portable",
  "production"
]);

export const MISSION_SETTLEMENT_PROFILES = Object.freeze([
  "none",
  "zeko"
]);

function booleanEnv(value) {
  if (value === undefined) return null;
  const normalized = String(value).toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  throw new Error("DEMO_MODE must be a boolean value.");
}

export function missionAuthProfile(env = process.env) {
  const configured = env.MISSION_AUTH_PROFILE;
  const demoMode = booleanEnv(env.DEMO_MODE);
  let profile;

  if (configured === "production_strict") {
    profile = "production";
  } else if (configured) {
    profile = configured;
  } else if (env.NODE_ENV === "production" || demoMode === false) {
    profile = "production";
  } else {
    profile = "demo";
  }

  if (!MISSION_AUTH_PROFILES.includes(profile)) {
    throw new Error(
      `MISSION_AUTH_PROFILE must be one of ${MISSION_AUTH_PROFILES.join(", ")}.`
    );
  }
  if (demoMode === true && profile !== "demo") {
    throw new Error("DEMO_MODE=true conflicts with a secure MISSION_AUTH_PROFILE.");
  }
  if (demoMode === false && profile === "demo") {
    throw new Error("DEMO_MODE=false conflicts with MISSION_AUTH_PROFILE=demo.");
  }
  if (env.NODE_ENV === "production" && profile === "demo") {
    throw new Error("MISSION_AUTH_PROFILE=demo is not allowed with NODE_ENV=production.");
  }
  return profile;
}

export function missionSettlementProfile(env = process.env) {
  const configured = env.MISSION_SETTLEMENT_PROFILE;
  if (configured) {
    if (!MISSION_SETTLEMENT_PROFILES.includes(configured)) {
      throw new Error(
        `MISSION_SETTLEMENT_PROFILE must be one of ${MISSION_SETTLEMENT_PROFILES.join(", ")}.`
      );
    }
    return configured;
  }

  // Preserve the original production behavior while allowing portable to
  // select production-grade auth without carrying a settlement dependency.
  if (
    env.MISSION_AUTH_PROFILE === "production" ||
    env.MISSION_AUTH_PROFILE === "production_strict" ||
    (!env.MISSION_AUTH_PROFILE &&
      (env.NODE_ENV === "production" || booleanEnv(env.DEMO_MODE) === false))
  ) {
    return "zeko";
  }
  return "none";
}

export function isProductionProfile(env = process.env) {
  return missionAuthProfile(env) !== "demo";
}

export function isZekoSettlementProfile(env = process.env) {
  return missionSettlementProfile(env) === "zeko";
}

export function isSettlementEnabled(env = process.env) {
  return missionSettlementProfile(env) !== "none";
}

export function verifierMode(options = {}, env = process.env) {
  return options.verifierMode ??
    env.MBA_VERIFIER_MODE ??
    (env.MISSION_AUTH_PROFILE === "production_strict" ? "production_strict" : null) ??
    (isProductionProfile(env) ? "production" : "compatibility");
}

export function isProductionStrictVerifier(options = {}, env = process.env) {
  return verifierMode(options, env) === "production_strict";
}

export function isDemoMode(env = process.env) {
  return missionAuthProfile(env) === "demo";
}

export function requireConfiguredValue(name, localFallback, purpose) {
  const value = process.env[name];
  if (value) return value;
  if (isProductionProfile()) {
    throw new Error(`${name} is required for production ${purpose}.`);
  }
  return localFallback;
}

export function bearerToken(req) {
  return String(req.headers.authorization ?? "").replace(/^Bearer\s+/i, "").trim();
}

export function requireAuthorityBearer(req, envName = "MISSION_APPROVAL_BEARER_TOKEN") {
  if (isDemoMode()) return { ok: true, mode: "demo" };
  const expected = process.env[envName];
  if (!expected) {
    return { ok: false, status: 500, reason: `${envName} is required in production profile.` };
  }
  const supplied = bearerToken(req);
  if (!supplied) {
    return { ok: false, status: 401, reason: "approval authority token is missing or invalid." };
  }
  const suppliedBuffer = Buffer.from(supplied);
  const expectedBuffer = Buffer.from(expected);
  if (suppliedBuffer.length !== expectedBuffer.length || !timingSafeEqual(suppliedBuffer, expectedBuffer)) {
    return { ok: false, status: 401, reason: "approval authority token is missing or invalid." };
  }
  return { ok: true, mode: missionAuthProfile() };
}
