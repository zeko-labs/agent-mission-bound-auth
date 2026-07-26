import { timingSafeEqual } from "node:crypto";

export function isProductionProfile(env = process.env) {
  return env.MISSION_AUTH_PROFILE === "production" ||
    env.MISSION_AUTH_PROFILE === "production_strict" ||
    env.NODE_ENV === "production" ||
    env.DEMO_MODE === "false";
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
  if (env.DEMO_MODE !== undefined) {
    return !["0", "false", "no", "off"].includes(String(env.DEMO_MODE).toLowerCase());
  }
  return !isProductionProfile(env);
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
  return { ok: true, mode: "production" };
}
