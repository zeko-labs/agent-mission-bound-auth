# Security Architecture

## Identity

MBA verifies OIDC authorization-code responses with PKCE, state, nonce, pinned
issuer and audience, expiry, and provider JWKS. Auth0, Okta, and configured
OIDC providers enter the same normalizer. Production rejects unmapped subjects.

The callback issues `mba-enterprise-identity-attestation-v1`, signed by the MBA
authority. Production passports and approvals require that attestation.
Production capabilities bind its hash and auth commitment, the signed approval,
policy, agent, Ed25519 checkpoint key, mission, budget, rails, and expiry. The
Zeko settlement profile additionally binds the Pallas holder key, trusted
domain verifier, proof statement, beneficiary, payout, and protocol fee.

## Keys

- OIDC keys remain with the provider.
- `MISSION_AUTHORITY_PRIVATE_JWK` signs portable identity, passport, approval,
  and capability objects.
- `MISSION_AUTHORITY_ZEKO_PRIVATE_KEY` authorizes registry approval and
  revocation changes in the Zeko settlement profile.
- `ZKAPP_PRIVATE_KEY` authorizes MissionRegistry deployment and one-time
  configuration.
- payer keys fund escrows; no payer key is required to submit a valid
  settlement proof.

Production keys belong in isolated KMS/HSM, wallet, or signing-service
boundaries. Verification-key hash and circuit digest must be pinned.

## Runtime Enforcement

Holder boundary events use public-key proofs. `production_strict` rejects
digest compatibility proofs. Stateful enforcement requires execution and
idempotency identifiers and applies exact integer microusd accounting. The JSON
state implementation is a sidecar reference; multi-instance production systems
must use transactional storage and serialized updates.

Portable passports bind the Ed25519 checkpoint key to the agent identity.
Zeko-settlement passports bind the Ed25519 and Pallas proof keys to the same
identity, and the capability carries the authority-signed Zeko binding.
Settlement accepts domain attestations only from Pallas keys listed in
`DOMAIN_VERIFIER_PALLAS_PUBLIC_KEYS_JSON`.

## ZK And Settlement

The MissionCompliance proof covers action/domain membership, holder signatures,
the trusted domain-verifier signature, trace continuity, expiry, aggregate
budget, and all public settlement commitments. MissionRegistry checks approval,
revocation, nullifier, receipt, and escrow witnesses before atomic payout and
fee release.

A receipt hash or JSON anchor never authorizes production settlement by itself.
Release requires:

1. strict receipt structure;
2. concrete o1js proof verification against the trusted key;
3. signed capability verification against the trusted mission-authority JWKS;
4. field-for-field capability, receipt, and proof statement matching;
5. domain proof evidence verification against the committed evidence and
   trusted Pallas attestation;
6. chain-backed Zeko transaction and registry verification; and
7. the same unspent nullifier in the capability binding, receipt, proof, and
   registry transition.

Portable authorization does not claim settlement finality. Its assurance ends
at signed identity, capability, holder event, replay, budget, and application
checkpoint verification. It requires neither a TEE nor a central compute
operator.

## x402

MBA uses x402 v2 `PAYMENT-REQUIRED`, `PAYMENT-SIGNATURE`, and
`PAYMENT-RESPONSE`, CAIP-2 network IDs, and integer base-unit amounts. Mock
payments and the legacy `PAYMENT` request header are rejected in production.
When settlement is active, production sends the exact client `PaymentPayload` and the
server-advertised `PaymentRequirements` to the configured facilitator's
`/verify` and `/settle` endpoints. MBA binds the returned payer, network, and
transaction into its receipt. The synchronous demo verifier fails closed in
production so it cannot be mistaken for settlement.

Portable mode advertises no payment rails and refuses the tutorial compute
route instead of silently invoking a facilitator.

## Privacy Boundary

Public artifacts contain commitments, roots, counters, public keys, and payout
amounts. Raw IdP tokens, subjects, prompts, dataset rows, browser selectors,
form values, credentials, and holder secrets do not belong in receipts or
anchors. `nullifierSeed` is never exported by a capability.

MBA proves mission compliance and a trusted verifier's attestation over the
domain proof and output commitments. It does not prove that an LLM chose the
best plan, that a merchant fulfilled an order, or that a domain verifier's
implementation is sound.

See [SECURITY.md](../SECURITY.md) for vulnerability reporting and the
[threat model](./threat-model.md) for actor assumptions.
