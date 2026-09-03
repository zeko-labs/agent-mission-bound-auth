# Agent Mission-Bound Auth Protocol 1.0 Draft

## Purpose

MBA answers:

> Is this holder, representing this verified principal through this agent,
> authorized to perform this mission, and did the resulting boundary trace
> satisfy its policy before settlement?

## Actors

- **Enterprise IdP:** Auth0, Okta, or another OIDC provider.
- **Mission authority:** normalizes identity and signs attestations, passports,
  approvals, and capabilities.
- **Approver:** verified human or policy principal authorizing the mission.
- **Holder:** agent runtime controlling the mission-bound key.
- **Domain app:** performs private compute or another external action.
- **Payer and beneficiary:** fund and receive mission settlement.
- **Verifier:** checks portable artifacts, proofs, and Zeko evidence.
- **MissionRegistry:** Zeko zkApp enforcing approval, revocation, nullifier,
  receipt, escrow, payout, and fee rules.

## Profiles

Authorization and settlement are independent protocol axes:

```text
MISSION_AUTH_PROFILE=demo | portable | production
MISSION_SETTLEMENT_PROFILE=none | zeko
```

`demo` permits deterministic fixtures, mock payments, and proofs-disabled local
simulation. `portable` requires production identity, authority signatures,
holder signatures, replay controls, and durable enforcement without requiring
settlement. `production` with `zeko` adds Pallas bindings, domain verification,
x402 settlement, MissionCompliance proofs, and MissionRegistry finality.

Verifiers MUST reject demo proof schemes in secure auth profiles. A portable
artifact MUST NOT claim Zeko settlement finality without the proof and
chain-backed registry evidence required by the settlement profile.

## Discovery

```text
GET /.well-known/agent-authorization.json
GET /.well-known/mission-authority-jwks.json
```

## Identity

The OIDC authorization-code flow uses PKCE, single-use state, nonce, provider
discovery, pinned issuer and client audience, expiry, and JWKS signature
verification. Provider claims normalize into agent, organization, scope, data,
rail, and budget claims.

`mba-enterprise-identity-attestation-v1` contains only hashed provider subject
identity, normalized grants, authorization commitments, expiry, and authority
JWS. Production passport and approval issuance requires this attestation.

`agent-passport-v1` identifies the agent, represented organization, vouching
IdP, Ed25519 checkpoint key, and authority signature. Zeko settlement passports
also bind the Pallas proof key.

## Mission, Approval, And Capability

`mission-bound-agent-auth-v1` defines task, resources, operation, actions,
scopes, rails, budget, checkpoints, privacy constraints, and expiry.

`mission-approval-v1` binds a verified approver and signed mission snapshot.

`mission-bound-capability-v1` binds:

```text
issuer and audience
principal and OIDC authorization commitments
identity-attestation and approval hashes
agent and runtime
holder key commitment
Zeko binding with the Pallas holder and trusted domain-verifier commitments
  when MISSION_SETTLEMENT_PROFILE=zeko
mission and policy hashes
allowed domains, actions, data scopes, and payment rails
exact decimal spend cap and expiry
jti and nullifier commitment
settlement release condition
authority JWS
```

Nullifier secrets are private and never exported. Renewal preserves identity,
mission, approval, policy, issuer, audience, and all holder and verifier keys
present in the active profile; uses a fresh `jti` and nullifier commitment; and
may only narrow authority.

## Boundary Events

Canonical high-value checkpoints are:

```text
before_payment_offer
before_private_compute
before_external_side_effect
after_receipt
```

Production events require a holder signature, mission execution ID,
idempotency key, expiry, and exact action/resource/payment context. Events form
an append-only hash chain. Public trace exports are redacted.

## MissionCompliance Statement

`mba-mission-compliance-proof-v1` is an o1js proof whose public input binds:

```text
mission, auth, capability, policy, approval, and holder commitments
trusted domain-verifier key commitment
allowed action and domain Merkle roots
dataset, domain proof, output, and payment commitments
trace root, receipt commitment, and nullifier
mission expiry, last observed slot, spend cap, actual spend, and event count
beneficiary, payout, and protocol fee
```

Private input contains commitment secrets, holder and domain-verifier public
keys, the domain-verifier signature, holder-signed events, and action/domain
membership witnesses. The v1 circuit supports four events and proves
contiguity, membership, both signature classes, expiry, trace, final payment
context, and aggregate budget.

The circuit verifies a mission-approved Pallas signature over the mission,
capability, policy, dataset, domain proof, and output commitments. Production
receipt verification then calls the configured domain adapter to validate the
proof's semantics. A composed domain circuit can replace the attestation model.

Canonical strings and objects map to o1js `Field` values by
`mba-zeko-encoding-v1`: canonical JSON or NFC string bytes, SHA-256, then
reduction modulo the Pallas field order. Monetary values use integer microusd
or asset base units. Zeko Ethereum Sepolia's native sETH uses 9-decimal base
units.

Zeko-bound v3 artifacts separate network identity by function:

```text
protocolNetworkId  zeko:sepolia   MBA capability, receipt, anchor, and x402 routing
graphqlNetworkId   zeko:testnet   value asserted by the live GraphQL endpoint
signingNetworkId   testnet        o1js/Auro transaction-signature domain
```

Verifiers accept legacy v2 artifacts with `network: zeko:testnet` or
`networkId: zeko:testnet`, but reject mixed v2/v3 fields and noncanonical v3
combinations.

## Registry And Settlement

MissionRegistry stores one namespaced Merkle root and sequence. Namespace keys
separate approvals, revocations, nullifiers, receipts, and escrows. Every root
transition advances the sequence.

Settlement requires:

1. valid MissionCompliance proof;
2. unexpired mission and escrow;
3. matching mission, beneficiary, payout, and fee;
4. approval membership;
5. revocation non-membership;
6. unused nullifier and receipt slots; and
7. active funded escrow.

The transaction consumes the nullifier, records the receipt, closes escrow, and
pays beneficiary plus fee recipient atomically. Any caller may submit a valid
proof; no relayer is trusted with settlement authority.

## x402

MBA uses x402 v2:

```text
server -> client  PAYMENT-REQUIRED
client -> server  PAYMENT-SIGNATURE
server -> client  PAYMENT-RESPONSE
```

Networks use CAIP-2 and amounts use integer asset base units. Ethereum and Base
use the EVM facilitator path. Arc and Tempo remain preview until chain-specific
facilitator and end-to-end settlement tests are enabled.

## Settlement Verification

A production Zeko settlement verifier:

1. validates strict schemas and authority JWS artifacts;
2. verifies the receipt's signed capability against trusted authority JWKS;
3. matches its Zeko binding and settlement nullifier to the receipt and proof;
4. checks holder events and receipt bindings;
5. verifies the concrete o1js proof against a pinned verification key and
   circuit digest;
6. verifies the domain proof evidence and its Pallas attestation;
7. checks that named public input matches serialized proof input;
8. confirms the Zeko transaction and registry state; and
9. rejects historical roots unless an archive-backed verifier proves the
   corresponding event.

The verifier targets Zeko's application-layer state and events. It does not
run or verify the network's Ethereum batch-settlement pipeline.

A receipt or client-computed anchor alone never authorizes payout.

Portable verification ends after trusted authority JWS validation, capability
binding, Ed25519 holder-event validation, trace continuity, replay protection,
budget enforcement, and the domain application's checkpoint decision. It does
not require or imply payout finality.

## Non-Goals

MBA does not define application-specific work, prove that an LLM reasoned
correctly, guarantee merchant fulfillment, or prove domain computation unless
the bound domain proof is independently verified.
