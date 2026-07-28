import { randomBytes, createHash } from "node:crypto";
import { sha256Hex } from "./digest.js";
import { buildAuthCommitment, fetchJwks, normalizeOAuthClaims, verifyJwtWithJwks } from "./oauth-production.js";
import { buildEnterpriseIdentityAttestation } from "./identity-attestations.js";
import { isProductionProfile } from "./runtime.js";

const AUTH0_DEFAULT_SCOPE = "openid profile email compute:clinical dataset:clinical-failures-q1 rail:zeko rail:base budget:small";
const OKTA_DEFAULT_SCOPE = "openid profile email";
const SESSION_TTL_MS = 10 * 60 * 1000;

function randomToken(bytes = 32) {
  return randomBytes(bytes).toString("base64url");
}

function pkceChallenge(verifier) {
  return createHash("sha256").update(verifier).digest("base64url");
}

function normalizeIssuer(issuer) {
  if (!issuer) return null;
  return issuer.endsWith("/") ? issuer : `${issuer}/`;
}

function auth0Issuer() {
  if (process.env.AUTH0_ISSUER) return normalizeIssuer(process.env.AUTH0_ISSUER);
  if (process.env.AUTH0_DOMAIN) return normalizeIssuer(`https://${process.env.AUTH0_DOMAIN.replace(/^https?:\/\//, "")}`);
  return null;
}

function customProviders() {
  if (!process.env.OIDC_PROVIDERS_JSON) return [];
  const parsed = JSON.parse(process.env.OIDC_PROVIDERS_JSON);
  if (!Array.isArray(parsed)) throw new Error("OIDC_PROVIDERS_JSON must be a JSON array.");
  return parsed.map((provider) => ({
    ...provider,
    provider: provider.provider ?? provider.id,
    issuer: normalizeIssuer(provider.issuer)
  }));
}

export function oidcProviderNames() {
  return Array.from(new Set(["auth0", "okta", ...customProviders().map((provider) => provider.provider).filter(Boolean)]));
}

export function oidcProviderConfig(provider, baseUrl) {
  const redirectUri = `${baseUrl.replace(/\/$/, "")}/api/oauth/callback`;
  if (provider === "auth0") {
    const issuer = auth0Issuer();
    return {
      provider,
      configured: Boolean(issuer && process.env.AUTH0_CLIENT_ID),
      issuer,
      clientId: process.env.AUTH0_CLIENT_ID,
      clientSecret: process.env.AUTH0_CLIENT_SECRET,
      audience: process.env.AUTH0_AUDIENCE,
      scope: process.env.AUTH0_SCOPE ?? AUTH0_DEFAULT_SCOPE,
      redirectUri,
      discoveryUrl: issuer ? `${issuer}.well-known/openid-configuration` : null
    };
  }
  if (provider === "okta") {
    const issuer = normalizeIssuer(process.env.OKTA_ISSUER);
    return {
      provider,
      configured: Boolean(issuer && process.env.OKTA_CLIENT_ID),
      issuer,
      clientId: process.env.OKTA_CLIENT_ID,
      clientSecret: process.env.OKTA_CLIENT_SECRET,
      audience: process.env.OKTA_AUDIENCE,
      scope: process.env.OKTA_SCOPE ?? OKTA_DEFAULT_SCOPE,
      redirectUri,
      discoveryUrl: issuer ? `${issuer}.well-known/openid-configuration` : null
    };
  }

  const custom = customProviders().find((item) => item.provider === provider);
  if (!custom) throw new Error(`Unsupported OIDC provider: ${provider}`);
  return {
    provider: custom.provider,
    configured: Boolean(custom.issuer && custom.clientId),
    issuer: custom.issuer,
    clientId: custom.clientId,
    clientSecret: custom.clientSecret,
    audience: custom.audience,
    scope: custom.scope ?? OKTA_DEFAULT_SCOPE,
    redirectUri: custom.redirectUri ?? redirectUri,
    discoveryUrl: custom.discoveryUrl ?? `${custom.issuer}.well-known/openid-configuration`
  };
}

export async function discoverOidcProvider(config) {
  if (!config.discoveryUrl) throw new Error(`${config.provider} issuer is not configured.`);
  const res = await fetch(config.discoveryUrl);
  if (!res.ok) throw new Error(`${config.provider} discovery failed with ${res.status}.`);
  const discovery = await res.json();
  const discoveredIssuer = normalizeIssuer(discovery.issuer);
  if (discoveredIssuer !== normalizeIssuer(config.issuer)) {
    throw new Error(`${config.provider} discovery issuer does not match configured issuer.`);
  }
  for (const [label, value] of [
    ["authorization_endpoint", discovery.authorization_endpoint],
    ["token_endpoint", discovery.token_endpoint],
    ["jwks_uri", discovery.jwks_uri]
  ]) {
    if (!value) throw new Error(`${config.provider} discovery is missing ${label}.`);
    const endpoint = new URL(value);
    if (endpoint.protocol !== "https:" && isProductionProfile()) {
      throw new Error(`${config.provider} ${label} must use HTTPS in production.`);
    }
  }
  return {
    issuer: discoveredIssuer,
    authorizationEndpoint: discovery.authorization_endpoint,
    tokenEndpoint: discovery.token_endpoint,
    jwksUri: discovery.jwks_uri,
    raw: discovery
  };
}

export async function buildOidcAuthorization(config, sessions) {
  if (!config.configured) throw new Error(`${config.provider} is missing issuer or client id.`);
  pruneOidcSessions(sessions);
  const discovery = await discoverOidcProvider(config);
  const state = randomToken();
  const nonce = randomToken();
  const codeVerifier = randomToken(48);
  const params = new URLSearchParams({
    response_type: "code",
    client_id: config.clientId,
    redirect_uri: config.redirectUri,
    scope: config.scope,
    state,
    nonce,
    code_challenge: pkceChallenge(codeVerifier),
    code_challenge_method: "S256"
  });
  if (config.audience) params.set("audience", config.audience);

  sessions.set(state, {
    provider: config.provider,
    issuer: discovery.issuer,
    audience: config.clientId,
    resourceAudience: config.audience,
    clientId: config.clientId,
    clientSecret: config.clientSecret,
    redirectUri: config.redirectUri,
    codeVerifier,
    nonce,
    tokenEndpoint: discovery.tokenEndpoint,
    jwksUri: discovery.jwksUri,
    createdAt: Date.now()
  });

  return {
    provider: config.provider,
    authorizationUrl: `${discovery.authorizationEndpoint}?${params.toString()}`,
    state,
    redirectUri: config.redirectUri,
    issuer: discovery.issuer
  };
}

function pruneOidcSessions(sessions) {
  const cutoff = Date.now() - SESSION_TTL_MS;
  for (const [state, session] of sessions.entries()) {
    if ((session.createdAt ?? 0) < cutoff) sessions.delete(state);
  }
}

export async function completeOidcAuthorization({ code, state }, sessions) {
  if (!code || !state) throw new Error("OIDC callback requires code and state.");
  const session = sessions.get(state);
  if (!session) throw new Error("OIDC state was not found or already used.");
  sessions.delete(state);
  if (
    !Number.isFinite(session.createdAt) ||
    Date.now() - session.createdAt > SESSION_TTL_MS
  ) {
    throw new Error("OIDC state expired.");
  }

  const form = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: session.redirectUri,
    client_id: session.clientId,
    code_verifier: session.codeVerifier
  });
  if (session.clientSecret) form.set("client_secret", session.clientSecret);

  const tokenRes = await fetch(session.tokenEndpoint, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: form
  });
  const tokenBody = await tokenRes.json();
  if (!tokenRes.ok) {
    throw new Error(`OIDC token exchange failed: ${tokenBody.error_description ?? tokenBody.error ?? tokenRes.status}`);
  }
  if (tokenBody.token_type && String(tokenBody.token_type).toLowerCase() !== "bearer") {
    throw new Error("OIDC token_type must be Bearer.");
  }

  const token = tokenBody.id_token;
  if (!token) throw new Error("OIDC provider did not return an id_token.");
  const jwks = await fetchJwks(session.jwksUri);
  const claims = await verifyJwtWithJwks(token, {
    issuer: session.issuer,
    audience: session.audience,
    jwks
  });
  if (claims.nonce !== session.nonce) {
    throw new Error("OIDC nonce mismatch.");
  }

  let authorizationClaims = claims;
  if (session.resourceAudience) {
    const accessTokenIsJwt =
      typeof tokenBody.access_token === "string" &&
      tokenBody.access_token.split(".").length === 3;
    if (!accessTokenIsJwt && isProductionProfile()) {
      throw new Error(
        "OIDC resource audience requires a verifiable JWT access token in production."
      );
    }
    if (accessTokenIsJwt) {
      const accessClaims = await verifyJwtWithJwks(
        tokenBody.access_token,
        {
          issuer: session.issuer,
          audience: session.resourceAudience,
          jwks
        }
      );
      authorizationClaims = {
        ...claims,
        scope:
          accessClaims.scope ??
          accessClaims.scp ??
          claims.scope,
        scp: accessClaims.scp ?? claims.scp,
        permissions:
          accessClaims.permissions ?? claims.permissions
      };
    }
  }
  const normalizedClaims = normalizeOAuthClaims(
    authorizationClaims,
    session.provider,
    {
      tokenHash: sha256Hex({
        idToken: token,
        accessToken: tokenBody.access_token ?? null
      })
    }
  );
  const commitment = buildAuthCommitment(
    normalizedClaims,
    randomToken(16),
    process.env.ZK_OAUTH_ISSUER_SECRET
  );
  const identityAttestation = buildEnterpriseIdentityAttestation({
    normalizedClaims,
    authCommitment: commitment.authCommitment,
    scopeCommitment: commitment.scopeCommitment
  });
  return {
    provider: session.provider,
    tokenType: tokenBody.token_type ?? "Bearer",
    normalizedClaims,
    authCommitment: commitment.authCommitment,
    scopeCommitment: commitment.scopeCommitment,
    issuerProofDigest: commitment.issuerProofDigest,
    identityAttestation
  };
}
