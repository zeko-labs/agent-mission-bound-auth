# Threat Model

Agent Mission-Bound Auth is a protocol for proving scoped authority and
boundary compliance for delegated or autonomous agent work. It is not a general
proof that an LLM reasoned correctly or that a third-party service fulfilled
its side of a transaction.

## Protected Assets

- user or organization authority
- private data and dataset access
- payment approval and settlement release
- external tool and API access
- merchant or service-provider side effects
- agent compensation and protocol fee settlement
- portable receipts and audit roots

## Actors

- **Represented principal**: user, organization, or service account on whose
  behalf an agent acts.
- **Mission issuer**: authority that issues agent passports, capabilities, and
  approvals.
- **Approver**: human, policy engine, governance workflow, or IdP-backed process
  that approves a mission.
- **Runtime holder**: agent runtime, wallet, key enclave, or sidecar holding the
  mission-bound key.
- **Verifier**: app, service, registry, or auditor checking capabilities,
  boundary events, receipts, anchors, or settlement state.
- **Relayer**: transport that forwards approvals, receipts, proofs, or
  settlement payloads.
- **Payment facilitator**: service that verifies or executes rail-specific
  payment settlement.
- **External agent or service**: downstream actor hired or invoked by the
  mission.

## Trusted Components

- mission authority signing keys
- configured enterprise IdP trust roots
- holder key environment or wallet approval surface
- configured domain-verifier Pallas trust roots and verifier implementation
- verifier implementation and canonicalization rules
- Zeko-compatible registry and settlement verification path
- production secret storage for authority and facilitator keys

## Untrusted Or Semi-Trusted Components

- LLM planner and generated tool calls
- browser pages, DOM content, and web apps
- relayer transport
- external tools and agents
- merchant or service fulfillment systems
- user-supplied callback payloads
- request-supplied JWKS, issuer, or audience values in production

## Security Guarantees

The protocol is designed to provide:

- scoped authority through mission-bound capabilities and approvals
- holder participation through holder-key-bound boundary events
- boundary compliance through checkpoint verification
- trace integrity through hash-chained boundary events
- receipt binding across mission, policy, data, output, payment, and anchor
- replay resistance through idempotency keys and on-chain nullifier state
- proof-gated, atomic escrow payout and protocol fee settlement
- domain-proof-attested output binding under a mission-approved verifier key

## Non-Guarantees

The protocol does not prove:

- that the LLM chose the best plan
- that every DOM event or browser state was captured
- that a malicious website behaved honestly
- that a merchant shipped goods or fulfilled a service
- that a downstream agent produced truthful domain-specific output
- that private computation is correct unless a domain proof or ZK circuit covers
  that computation

The key line: MBA proves authority and boundary compliance, not omniscient
agent correctness.

## Production Expectations

All secure production profiles should:

- verify enterprise JWTs against pinned issuer, audience, expiry, nonce, and
  JWKS trust roots
- reject unmapped agent subjects
- require signed mission approvals
- use durable replay, budget, and revocation state
- reject demo digest holder proofs and require a public-key or ZK-friendly
  holder proof scheme such as `ed25519-holder-proof-v1`

Zeko settlement production should additionally:

- use durable registry witness state
- anchor approvals and settle proof-bound receipts through MissionRegistry
- require concrete o1js proof verification and live/archive Zeko verification
- pin domain-verifier Pallas keys and run the domain-specific evidence verifier
- reject production-final receipts with metadata-only proof or anchor evidence

Portable browser and extension authorization does not trust an MBA compute
operator or TEE. Its holder key can remain client-side, while each domain
application remains responsible for enforcing the checkpoint before its own
side effect.
