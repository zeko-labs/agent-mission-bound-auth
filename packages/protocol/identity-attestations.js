import { id, sha256Hex } from "./digest.js";
import { jwks, signJws, verifyJws } from "./authority-keys.js";
import { validateArtifactSchema } from "./schema-validation.js";

export const ENTERPRISE_IDENTITY_ATTESTATION_VERSION =
  "mba-enterprise-identity-attestation-v1";

function attestationBody(input = {}) {
  const claims = input.normalizedClaims;
  if (!claims?.issuer || !claims?.subject || !claims?.agentId) {
    throw new TypeError("Verified normalized OIDC claims are required.");
  }
  if (!input.authCommitment || !input.scopeCommitment) {
    throw new TypeError("OIDC authorization commitments are required.");
  }
  const issuedAt = input.issuedAt ?? new Date().toISOString();
  const issuedAtMs = Date.parse(issuedAt);
  const providerExpiry = Date.parse(claims.expiresAt);
  const ttlMs = Number(input.ttlMs ?? 10 * 60 * 1000);
  if (
    !Number.isFinite(issuedAtMs) ||
    !Number.isFinite(providerExpiry) ||
    !Number.isFinite(ttlMs) ||
    ttlMs <= 0 ||
    providerExpiry <= issuedAtMs
  ) {
    throw new TypeError("OIDC claim and attestation expiry must be valid and future bounded.");
  }
  const requestedExpiry = issuedAtMs + ttlMs;
  const expiry = Math.min(providerExpiry, requestedExpiry);
  return {
    version: ENTERPRISE_IDENTITY_ATTESTATION_VERSION,
    issuer: input.issuer ?? "agent-mission-bound-auth",
    source: {
      protocol: "oidc",
      provider: claims.provider,
      issuer: claims.issuer,
      subjectHash: sha256Hex({
        issuer: claims.issuer,
        subject: claims.subject
      }),
      audience: claims.audience,
      tokenHash: claims.tokenHash,
      tokenExpiresAt: claims.expiresAt
    },
    principal: {
      agentId: claims.agentId,
      organization: claims.organization,
      represents: claims.represents ?? null
    },
    grants: {
      scopes: claims.scopes,
      computeScopes: claims.computeScopes,
      datasetScopes: claims.datasetScopes,
      railScopes: claims.railScopes,
      maxSpendUsd: claims.budget?.maxSpendUsd ?? "0.00"
    },
    authCommitment: input.authCommitment,
    scopeCommitment: input.scopeCommitment,
    issuedAt,
    expiresAt: new Date(expiry).toISOString(),
    jti: input.jti ?? id("identity_attestation", {
      tokenHash: claims.tokenHash,
      authCommitment: input.authCommitment,
      issuedAt
    })
  };
}

export function buildEnterpriseIdentityAttestation(input = {}) {
  const body = attestationBody(input);
  return {
    ...body,
    attestationHash: sha256Hex(body),
    authorityJws: signJws(body, {
      typ: "mba-enterprise-identity-attestation+jwt"
    })
  };
}

export function verifyEnterpriseIdentityAttestation(
  attestation,
  options = {}
) {
  if (!attestation || typeof attestation !== "object") {
    return { valid: false, reason: "Missing enterprise identity attestation." };
  }
  const schema = validateArtifactSchema(
    "enterprise-identity-attestation",
    attestation
  );
  if (!schema.valid) return schema;
  if (attestation.version !== ENTERPRISE_IDENTITY_ATTESTATION_VERSION) {
    return { valid: false, reason: "Unsupported enterprise identity attestation." };
  }
  const { attestationHash, authorityJws, ...body } = attestation;
  if (attestationHash !== sha256Hex(body)) {
    return { valid: false, reason: "Enterprise identity attestation hash mismatch." };
  }
  if (!authorityJws) {
    return { valid: false, reason: "Enterprise identity attestation is unsigned." };
  }
  try {
    const verified = verifyJws(
      authorityJws,
      options.jwks ?? jwks(),
      { typ: "mba-enterprise-identity-attestation+jwt" }
    );
    if (sha256Hex(verified.payload) !== attestationHash) {
      return { valid: false, reason: "Identity attestation JWS payload mismatch." };
    }
  } catch (error) {
    return {
      valid: false,
      reason: error instanceof Error ? error.message : "Identity attestation JWS is invalid."
    };
  }
  const expiry = Date.parse(attestation.expiresAt);
  const issuedAt = Date.parse(attestation.issuedAt);
  const tokenExpiry = Date.parse(attestation.source?.tokenExpiresAt);
  const now = options.now ?? Date.now();
  const clockToleranceMs =
    Number(options.clockToleranceSeconds ?? 60) * 1000;
  if (
    Number.isNaN(issuedAt) ||
    Number.isNaN(expiry) ||
    Number.isNaN(tokenExpiry) ||
    issuedAt > now + clockToleranceMs ||
    expiry <= issuedAt ||
    expiry > tokenExpiry ||
    (!options.allowExpired && expiry <= now)
  ) {
    return { valid: false, reason: "Enterprise identity attestation has invalid issuance or expiry bounds." };
  }
  const expected = [
    ["agentId", options.agentId, attestation.principal?.agentId],
    ["organization", options.organization, attestation.principal?.organization],
    ["authCommitment", options.authCommitment, attestation.authCommitment]
  ];
  for (const [label, wanted, actual] of expected) {
    if (wanted !== undefined && wanted !== actual) {
      return { valid: false, reason: `Enterprise identity attestation ${label} mismatch.` };
    }
  }
  return {
    valid: true,
    attestationHash,
    agentId: attestation.principal.agentId,
    organization: attestation.principal.organization,
    authCommitment: attestation.authCommitment,
    source: attestation.source
  };
}
