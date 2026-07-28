import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";
import { hmacSha256Hex, sha256Hex } from "./digest.js";
import { isProductionProfile, requireConfiguredValue } from "./runtime.js";
import { usdToMicrousd } from "./zeko-encoding.js";

function base64urlDecode(value) {
  return Buffer.from(value, "base64url");
}

function parseJwt(token) {
  const parts = String(token ?? "").split(".");
  if (parts.length !== 3) {
    throw new Error("JWT must have header, payload, and signature parts.");
  }

  return {
    header: JSON.parse(base64urlDecode(parts[0]).toString("utf8")),
    payload: JSON.parse(base64urlDecode(parts[1]).toString("utf8")),
    signingInput: `${parts[0]}.${parts[1]}`,
    signature: base64urlDecode(parts[2])
  };
}

function jwkToKey(jwk) {
  return createPublicKey({ key: jwk, format: "jwk" });
}

function algorithmToNodeVerify(alg) {
  if (alg === "RS256") return "RSA-SHA256";
  if (alg === "RS384") return "RSA-SHA384";
  if (alg === "RS512") return "RSA-SHA512";
  throw new Error(`Unsupported JWT alg: ${alg}`);
}

export async function fetchJwks(jwksUrl) {
  const res = await fetch(jwksUrl);
  if (!res.ok) {
    throw new Error(`JWKS fetch failed with ${res.status}.`);
  }
  const body = await res.json();
  if (!Array.isArray(body.keys)) {
    throw new Error("JWKS response must include keys[].");
  }
  return body;
}

export async function verifyJwtWithJwks(token, options) {
  if (!options?.issuer || !options?.audience) {
    throw new Error("JWT verification requires pinned issuer and audience.");
  }
  const parsed = parseJwt(token);
  if (
    parsed.header.crit !== undefined &&
    (
      !Array.isArray(parsed.header.crit) ||
      parsed.header.crit.length > 0
    )
  ) {
    throw new Error("JWT critical headers are not supported.");
  }
  const jwks = options.jwks ?? await fetchJwks(options.jwksUrl);
  const key = jwks.keys.find((candidate) => candidate.kid === parsed.header.kid);
  if (!key) {
    throw new Error(`No JWKS key found for kid ${parsed.header.kid}.`);
  }
  if (key.use && key.use !== "sig") {
    throw new Error("JWKS key is not marked for signature verification.");
  }
  if (key.alg && key.alg !== parsed.header.alg) {
    throw new Error("JWT alg does not match JWKS key alg.");
  }

  const valid = verifySignature(
    algorithmToNodeVerify(parsed.header.alg),
    Buffer.from(parsed.signingInput),
    jwkToKey(key),
    parsed.signature
  );
  if (!valid) {
    throw new Error("JWT signature is invalid.");
  }

  const nowSeconds = Math.floor(Date.now() / 1000);
  const clockToleranceSeconds = Number(options.clockToleranceSeconds ?? 60);
  if (
    !Number.isFinite(clockToleranceSeconds) ||
    clockToleranceSeconds < 0 ||
    clockToleranceSeconds > 300
  ) {
    throw new Error("JWT clock tolerance must be between 0 and 300 seconds.");
  }
  if (options.issuer && parsed.payload.iss !== options.issuer) {
    throw new Error("JWT issuer mismatch.");
  }
  const audiences = Array.isArray(parsed.payload.aud) ? parsed.payload.aud : [parsed.payload.aud];
  if (options.audience && !audiences.includes(options.audience)) {
    throw new Error("JWT audience mismatch.");
  }
  if (
    audiences.length > 1 &&
    parsed.payload.azp !== options.audience
  ) {
    throw new Error("JWT azp must match audience when aud has multiple values.");
  }
  if (!parsed.payload.sub) {
    throw new Error("JWT subject is required.");
  }
  if (typeof parsed.payload.exp !== "number") {
    throw new Error("JWT exp is required.");
  }
  if (typeof parsed.payload.iat !== "number") {
    throw new Error("JWT iat is required.");
  }
  if (parsed.payload.iat > nowSeconds + clockToleranceSeconds) {
    throw new Error("JWT iat is in the future.");
  }
  if (
    options.maxTokenAgeSeconds !== undefined &&
    nowSeconds - parsed.payload.iat >
      Number(options.maxTokenAgeSeconds) + clockToleranceSeconds
  ) {
    throw new Error("JWT exceeds maximum token age.");
  }
  if (parsed.payload.exp <= nowSeconds - clockToleranceSeconds) {
    throw new Error("JWT is expired.");
  }
  if (typeof parsed.payload.nbf === "number" && parsed.payload.nbf > nowSeconds + clockToleranceSeconds) {
    throw new Error("JWT is not active yet.");
  }

  return parsed.payload;
}

function splitScopes(value) {
  if (Array.isArray(value)) return value.flatMap(splitScopes);
  if (typeof value === "string") return value.split(/[,\s]+/).filter(Boolean);
  return [];
}

function unique(values) {
  return Array.from(new Set(values.filter(Boolean))).sort();
}

export function normalizeOAuthClaims(
  claims,
  provider = "generic-oidc",
  context = {}
) {
  if (!claims?.iss || !claims?.sub) {
    throw new Error("OIDC claims must include issuer and subject.");
  }
  const rawScopes = unique([
    ...splitScopes(claims.scope),
    ...splitScopes(claims.scp),
    ...splitScopes(claims.permissions),
    ...splitScopes(claims["https://private-compute.example/scopes"])
  ]);
  const org =
    claims.org_id ??
    claims.organization ??
    claims.tid ??
    claims.tenant_id ??
    claims["https://private-compute.example/org"] ??
    "unknown-org";
  const maxSpendUsd =
    claims.max_spend_usd ??
    claims.maxSpendUsd ??
    claims["https://private-compute.example/max_spend_usd"] ??
    "0.00";
  usdToMicrousd(String(maxSpendUsd));

  const subjectKey = `${provider}:${claims.iss}:${claims.sub}`;
  const agentMap = loadAgentMappings();
  const mappedAgent = agentMap.get(subjectKey) ?? agentMap.get(`${claims.iss}:${claims.sub}`);
  if (isProductionProfile() && !mappedAgent) {
    throw new Error(`No production agent mapping found for ${subjectKey}.`);
  }
  const tokenAgentId =
    claims.agent_id ??
    claims["https://private-compute.example/agent_id"] ??
    claims.azp ??
    claims.client_id ??
    claims.sub;

  return {
    version: "normalized-oauth-claims-v1",
    provider,
    issuer: claims.iss,
    subject: claims.sub,
    subjectKey,
    audience: claims.aud,
    agentId: mappedAgent?.agentId ?? tokenAgentId,
    represents: mappedAgent?.represents ?? null,
    organization: String(
      mappedAgent?.organization ??
      mappedAgent?.represents?.id ??
      org
    ),
    scopes: rawScopes,
    computeScopes: rawScopes.filter((scope) => scope.startsWith("compute:")),
    datasetScopes: rawScopes.filter((scope) => scope.startsWith("dataset:")),
    railScopes: rawScopes.filter((scope) => scope.startsWith("rail:")),
    budget: {
      maxSpendUsd: String(maxSpendUsd)
    },
    issuedAt: claims.iat ? new Date(Number(claims.iat) * 1000).toISOString() : null,
    expiresAt: claims.exp ? new Date(Number(claims.exp) * 1000).toISOString() : null,
    tokenHash: context.tokenHash ?? sha256Hex({
      iss: claims.iss,
      sub: claims.sub,
      aud: claims.aud,
      exp: claims.exp,
      iat: claims.iat
    })
  };
}

function loadAgentMappings() {
  if (!process.env.AGENT_MAPPINGS_JSON) return new Map();
  const parsed = JSON.parse(process.env.AGENT_MAPPINGS_JSON);
  const entries = Array.isArray(parsed) ? parsed : Object.entries(parsed).map(([subjectKey, value]) => ({ subjectKey, ...value }));
  return new Map(entries.map((entry) => [entry.subjectKey, entry]));
}

export function buildAuthCommitment(normalizedClaims, salt, issuerSecret) {
  const secret = issuerSecret ?? requireConfiguredValue(
    "ZK_OAUTH_ISSUER_SECRET",
    "local-demo-issuer-secret",
    "authorization commitments"
  );
  const commitmentBody = {
    normalizedClaims,
    salt
  };
  return {
    authCommitment: sha256Hex(commitmentBody),
    scopeCommitment: sha256Hex({ scopes: normalizedClaims.scopes, salt }),
    issuerProofDigest: hmacSha256Hex(secret, commitmentBody),
    commitmentBody
  };
}
