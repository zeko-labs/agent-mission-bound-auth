# Security Notes

## Demo Keys

The default mission-authority key is embedded for local demonstration only.

Production deployments must run with `MISSION_AUTH_PROFILE=production` and `DEMO_MODE=false`.
For settlement release paths and browser/helper-agent production flows, use
`MBA_VERIFIER_MODE=production_strict`.
They must set:

```text
ZK_OAUTH_ISSUER_SECRET
MISSION_AUTHORITY_PRIVATE_JWK
MISSION_APPROVAL_BEARER_TOKEN
```

from a secret manager or HSM-backed key source.

## Enterprise Identity

SAML/OIDC providers remain the upstream source of enterprise identity.

Production deployments should configure:

```text
OIDC_ISSUER
OIDC_AUDIENCE
OIDC_JWKS_URL
```

The OIDC callback path requires an ID token, validates JWKS signatures, issuer,
client-id audience, expiry, and nonce, then normalizes provider claims before
creating commitments. Access tokens should be handled by protected resource
APIs, not as agent identity tokens.

Production commitment construction pins verification to configured provider
trust roots. Request-supplied issuer, audience, and JWKS URLs are ignored in
production because they would let a caller bring their own signing authority.

Map provider subjects into internal agent records with `AGENT_MAPPINGS_JSON`.
Use `provider:issuer:subject` as the stable key.
In production, unmapped subjects are rejected and server-side mappings take
precedence over token-supplied agent identifiers.

## Key Rotation

The JWKS endpoint supports key IDs. Production should publish overlapping old/new keys during rotation and include issuer metadata in discovery.

## Replay

Mission approvals include:

- mission hash
- mission snapshot
- expiry
- approved tools/scopes/rails
- approved checkpoints

Checkpoint verification enforces approval expiry, approval hash/id integrity,
agent binding, dataset binding, operation binding, rail binding, action binding,
scope binding, and checkpoint binding.

`/api/mission/verify-checkpoint` is stateless. It verifies the approval and
returns the receipt shape without mutating replay, budget, ordering, or log
state.

`/api/mission/enforce-checkpoint` is stateful. In production profile it requires
`MISSION_APPROVAL_BEARER_TOKEN`, `missionExecutionId`, and an idempotency key for
compute or side-effect checkpoints. Domain apps should include action-specific
context in checkpoint verification and persist the resulting enforcement
receipt.

Budget counters are tracked per approval when `context.spendUsd` or
`context.amountUsd` is supplied. In production, mission/enforcement state is
persisted to `MISSION_STATE_PATH`.

## Browser Helper Agents

Browser/helper agents should use `mba-browser-mission-profile-v1`,
`mba-redacted-trace-v1`, `mba-human-handoff-v1`, and
`mba-execution-bundle-v1`. Public exports must contain only commitments,
hashes, canonical action vocabulary, stop reasons, and verifier links. Raw
URLs, selectors, page text, form values, addresses, emails, and payment labels
belong only in owner-controlled private traces.

`production_strict` rejects demo digest proofs and compatibility holder proofs.
It requires Ed25519 or stronger holder proofs, expiry, idempotency keys,
holder-key commitments, proof statement evidence, and Zeko anchor evidence for
final receipt verification.

## Revocation

The implementation includes an off-chain revocation registry for auth
commitments. In production it persists to `REVOCATION_STATE_PATH`. Production
should pair this with either:

- short-lived approvals, or
- an anchored revocation/root model.

## What Is ZK Today

Live Zeko anchoring exists for:

- approval root updates
- execution receipt root updates

The current private-compute demo does not prove the computation itself in-circuit. It anchors commitments to the approval, data, policy, output, payment context, and receipt.

## Payment Settlement

Production x402 verification rejects mock facilitator payments. The current
production path requires signed facilitator receipts with
`X402_TRUST_FACILITATOR_RECEIPTS=true`, `X402_FACILITATOR_ISSUER`, and
`X402_FACILITATOR_JWKS_JSON`. The signed receipt must bind request id, payment
id, rail, network, amount, asset, payer, payee, authorization digest, and a
transaction hash or settlement id.

Settlement release requires an anchored receipt/root, a valid lifecycle
transition to `settlement_release_allowed`, an unused nullifier, and policy
approval for the payment rail.

## What Is Not Yet Production-Hardened

- hosted facilitator settlement for every payment rail
- production persistence for roots and witnesses
- HSM/KMS integration for mission-authority keys
- on-chain revocation root

## Production Checklist

- Store `MISSION_AUTHORITY_PRIVATE_JWK` in KMS/HSM-backed secret storage.
- Set `MISSION_AUTH_PROFILE=production` and `DEMO_MODE=false`.
- Set `ZK_OAUTH_ISSUER_SECRET` and `MISSION_APPROVAL_BEARER_TOKEN`.
- Set `MISSION_STATE_PATH` and `REVOCATION_STATE_PATH`.
- Publish overlapping JWKS keys during rotation.
- Set `OIDC_ISSUER`, `OIDC_AUDIENCE`, and `OIDC_JWKS_URL`.
- Configure `AGENT_MAPPINGS_JSON` for each enterprise customer subject mapping.
- Persist missions, approvals, revocations, enforcement receipts, and Zeko root witnesses.
- Enforce short approval TTLs for autonomous agents.
- Use capability renewal instead of long-lived autonomous-agent capabilities.
- Run browser/helper-agent settlement paths in `production_strict` verifier mode.
- Require signed facilitator receipts or live chain verification for x402 payments.
- Set `PRIVATE_COMPUTE_MIN_COHORT` for aggregate-only output policy.
- Anchor approval roots and receipt roots on Zeko on a repeatable operator schedule.
- Run remote conformance against every deployment.
