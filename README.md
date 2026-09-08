# Agent Mission-Bound Auth

Agent Mission-Bound Auth (MBA) is a source-available protocol kit for
authorizing autonomous agent work by mission, proving compliance without
revealing private inputs, and settling approved work on Zeko.

The app in `apps/harness` is a local tutorial sidecar. The protocol, schemas,
SDK, verifier, ZK program, and registry are the reusable product.

MBA has three adoption layers:

- **Demo:** deterministic holder proofs, mock x402, and proofs-disabled local
  simulation for tutorials and implementation testing.
- **Portable authorization:** real OIDC, signed capabilities, Ed25519 boundary
  events, replay and budget enforcement, and redacted browser/extension
  receipts without a compute operator, TEE, x402 facilitator, or chain.
- **Zeko settlement:** Pallas-bound domain verification, real compliance
  proofs, x402 settlement, registry nullifiers, receipt anchors, escrow, and
  conditional sETH payouts on Zeko Ethereum Sepolia.

See [protocol profiles](./docs/profiles.md) for guarantees and configuration.
See [Zeko Ethereum Sepolia](./docs/zeko-ethereum-sepolia.md) for the active
network profile and deployment procedure.

## What MBA Solves

- **Agent identity:** verifies Auth0, Okta, or generic OIDC tokens against
  discovery and JWKS, then issues a signed enterprise identity attestation.
- **Agent scope:** binds identity, agent, Ed25519 checkpoint key, Pallas proof
  key, task, actions, domains, data scopes, rails, budget, approval, and expiry
  into a signed capability.
- **Agent approval:** records an authority-signed approval commitment in the
  Zeko MissionRegistry.
- **Agent enforcement:** proves holder-signed boundary events stayed within
  action, domain, expiry, trace, and aggregate-spend constraints.
- **Agent commerce:** binds x402 v2 payment context and a trusted domain
  verifier attestation to the proof, then atomically releases the beneficiary
  payout and protocol fee only once.

## Zeko Core

MBA targets the live Zeko Ethereum Sepolia application layer at
`https://sepolia.zeko.io/graphql`. It continues to use ordinary o1js zkApps,
Pallas keys, B62 addresses, and the `testnet` transaction-signing domain. The
native asset is 9-decimal sETH. MBA does not operate an Ethereum batch
settler, bridge, or Ethereum RPC client; those are network responsibilities,
just as block production was not part of the application protocol.

MBA keeps three network identifiers separate: `zeko:sepolia` is the canonical
MBA protocol and x402 rail identifier, GraphQL currently reports
`zeko:testnet`, and o1js/Auro sign with `testnet`. The first is an MBA routing
identifier, not a replacement for either network value supplied by Zeko.

`zkapp/MissionComplianceProgram.ts` proves a bounded mission trace. Its public
statement includes the identity, capability, policy, approval, holder, trusted
domain verifier, dataset, domain-proof, output, payment, receipt, nullifier,
beneficiary, payout, and fee commitments. Private witnesses include holder
identity, a domain-verifier signature, commitment secrets, and boundary events.

`zkapp/MissionRegistry.ts` maintains one namespaced Merkle root for approvals,
revocations, nullifiers, receipts, and mission escrows. Settlement verifies the
proof, consumes the nullifier, records the receipt, closes the escrow, and pays
the beneficiary and fee recipient in one Zeko transaction.

MBA proves mission-policy compliance and that a mission-approved Pallas domain
verifier attested to the exact dataset, domain proof, and output commitments.
Production receipt verification also runs the domain-specific verifier against
the disclosed proof evidence before declaring settlement valid.

## Quick Start

```bash
npm install
npm start
```

Open `http://127.0.0.1:8787`.

```bash
npm run test:demo
npm run test:portable
npm run test:ci
npm run test:zeko-inputs
```

Generate and verify real proofs separately because compilation is expensive:

```bash
npm run zkapp:compile-proof-system -- --out build/mission-compliance-vk.json
npm run test:zkapp-trustless:proofs
```

## Enterprise OIDC

Keep provider credentials in `.env.local`; never commit them.

```bash
AUTH0_ISSUER=https://tenant.us.auth0.com/
AUTH0_CLIENT_ID=...
AUTH0_CLIENT_SECRET=...

OKTA_ISSUER=https://tenant.okta.com
OKTA_CLIENT_ID=...
OKTA_CLIENT_SECRET=...
```

Provider callback:

```text
http://127.0.0.1:8787/api/oauth/callback
```

For portable production authorization, start from `.env.portable.example`.
It uses `MISSION_AUTH_PROFILE=portable` and
`MISSION_SETTLEMENT_PROFILE=none`.

For full Zeko settlement, set `MISSION_AUTH_PROFILE=production`,
`MISSION_SETTLEMENT_PROFILE=zeko`, `DEMO_MODE=false`, `PUBLIC_BASE_URL`,
`MISSION_AUTHORITY_PRIVATE_JWK`,
`MISSION_APPROVAL_BEARER_TOKEN`, `ZK_OAUTH_ISSUER_SECRET`, durable state paths,
server-side `AGENT_MAPPINGS_JSON`, and
`DOMAIN_VERIFIER_PALLAS_PUBLIC_KEYS_JSON`. Production passport and approval
issuance requires the signed identity attestation returned by the verified OIDC
callback. See [OAuth setup](./docs/oauth-sandbox.md).

## Proof Input Compiler

`prepareMissionComplianceBinding` creates the authority-visible Zeko binding
and holder-private witness material. `createDomainProofAttestation` lets an
approved domain verifier attest the exact proof evidence and output.
`buildMissionComplianceInputs` validates both keys and compiles canonical
allowlist roots, signatures, trace, spend, nullifier, and receipt values into
the o1js public input and witness.

```js
const prepared = await prepareMissionComplianceBinding({
  holderPrivateKey,
  domainVerifierPublicKey,
  beneficiary,
  missionIdHash,
  authCommitment,
  principalHash,
  agentId,
  datasetId,
  dataScopes,
  allowedActions,
  allowedDomains,
  validUntilSlot,
  maxSpendUsd,
  payoutNative,       // decimal sETH
  protocolFeeNative  // decimal sETH
});
```

The mission authority signs `prepared.binding` inside the capability. Keep
`prepared.privateWitnessMaterial` in the holder's protected runtime.

## Protocol Endpoints

```text
GET  /.well-known/agent-authorization.json
GET  /.well-known/mission-authority-jwks.json
GET  /api/oauth/login?provider=auth0|okta|customer-idp
GET  /api/oauth/callback
POST /api/agents/passport
POST /api/missions/propose
POST /api/missions/approve
POST /api/capabilities/issue
POST /api/mission/verify-checkpoint
POST /api/mission/enforce-checkpoint
POST /api/mission/export-bundle
```

`verify-checkpoint` performs portable authorization checks.
`enforce-checkpoint` also mutates replay, ordering, and exact microusd budget
state and is bearer-gated in production.

## x402 v2

MBA's x402 adapter emits `PAYMENT-REQUIRED`, accepts `PAYMENT-SIGNATURE`, and returns
`PAYMENT-RESPONSE`. Amounts are integer asset base units. The Zeko rail uses
the MBA protocol identifier `zeko:sepolia`; Ethereum and Base use CAIP-2 IDs
and the EVM facilitator path. Arc and Tempo are
clearly marked preview rails until their production facilitator adapters and
end-to-end chain tests are configured. In production, MBA submits the selected
payment payload and the verbatim advertised requirement to the facilitator's
`/verify` and `/settle` endpoints before issuing its payment receipt.

The adapter does not modify or fork the x402 protocol. Portable authorization
does not advertise settlement rails and does not call a facilitator.

## Zeko Operations

The canonical Zeko Sepolia `MissionRegistry` is
`B62qpBXMbrKVJwcS9wQN7SpFb6jkrXn2xrntCoM6D461qL2sYZarPHi`. Its public
deployment and acceptance evidence is stored in
`data/deployment.mission-registry.zeko-sepolia.json`.

The frozen v0 `PrivateComputeAccess` contract remains in the repository for
source and deployed-contract compatibility. Its state and verification key are
not compatible with `MissionRegistry`; this fresh Sepolia deployment reuses
the historic B62 public identity but starts with a distinct v1 contract state.
See the
[v0 deployment record](./docs/legacy-private-compute-access-v0.md).

```bash
npm run zkapp:deploy
npm run zkapp:anchor-approval
npm run zkapp:revoke-capability
npm run zkapp:fund-mission
npm run zkapp:settle-mission
npm run zkapp:refund-mission
npm run zkapp:get-state
```

Scripts consume JSON from stdin and maintain
`MISSION_REGISTRY_STATE_PATH`, an atomic, Sepolia-scoped local Merkle witness
index. Production
operators should place this index in transactional, access-controlled storage
and serialize writers.

The v1 circuit field names `payoutNanomina` and `protocolFeeNanomina` are
retained to preserve the compiled proof identity. On the active Sepolia
deployment they contain native sETH base units. Builder-facing inputs and
anchors use `payoutNativeUnits` and `protocolFeeNativeUnits` aliases.

## Verification

```bash
mba verify receipt receipt.json
mba verify bundle execution-bundle.json
mba verify trace trace.json
mba verify anchor receipt.json anchor.json
mba verify settlement receipt.json anchor.json \
  --verification-key verification-key.json \
  --authority-jwks authority-jwks.json \
  --domain-verifier domain-verifier.mjs \
  --graphql https://sepolia.zeko.io/graphql \
  --registry B62...
```

A structurally valid receipt is not settlement authority. Production release
requires a valid `mba-mission-compliance-proof-v1`, a trusted verification key,
a trusted mission-authority JWKS, a trusted domain-verifier module, and
chain-backed
`mba-zeko-registry-anchor-v3` verification. The verifier continues to accept
legacy v2 anchors whose single `networkId` was `zeko:testnet`.

## Layout

```text
packages/protocol  protocol objects, OIDC, x402, proof and chain verification
packages/sdk       client and verifier exports
zkapp              v0 compatibility contract, MissionCompliance, MissionRegistry
schemas            strict portable artifact schemas
scripts            conformance, adversarial, Zeko, and verifier tooling
apps/harness       local tutorial sidecar
```

Start with the [protocol spec](./docs/spec.md),
[threat model](./docs/threat-model.md), and
[security policy](./SECURITY.md).

## License

Agent Mission-Bound Auth is part of the Zeko Agent Protocol Bundle. Protected
product/protocol-layer code is licensed under BUSL-1.1 with the Zeko Additional
Use Grant. Adoption-layer materials may be Apache-2.0 or MIT where expressly
marked.

The current Change Date is 2030-07-17, and the Change License is Apache
License, Version 2.0. Non-production/testnet use is free under the Additional
Use Grant. Independent Agent Protocol Bundle production deployments are covered
by the self-serve commercial deployment license. The current published
self-serve fee is $0/year, subject to the pricing schedule in
[PRICING.md](./PRICING.md).

Using the Official Zeko Network or official Zeko-operated or Zeko-authorized
Agent Protocol Bundle services does not require a separate commercial
deployment license; users and integrators pay the ordinary network, service,
usage, transaction, marketplace, gas, prover, bridge, or similar fees applicable
to those official deployments.

Standard self-serve pricing is published in [PRICING.md](./PRICING.md):

- Protocol Layer Production Deployments: $0/year per production rollup under
  the current published self-serve pricing.
- Independent Agent Protocol Deployments: $0/year per deploying legal entity
  per Deployment Network under the current published self-serve pricing.

Current self-serve pricing is subject to change by a successor pricing schedule,
ecosystem exception, enterprise agreement, foundation agreement, or other
written authorization published or approved by Zeko Labs.

The self-serve commercial deployment license covers license rights only.
Managed deployment, enterprise support, compliance review, SLAs, custom
integrations, and dedicated infrastructure are separate commercial services.

See [LICENSING.md](./LICENSING.md), [LICENSE](./LICENSE),
[LICENSES/ZEKO-ADDITIONAL-USE-GRANT.md](./LICENSES/ZEKO-ADDITIONAL-USE-GRANT.md),
[COMMERCIAL-TERMS.md](./COMMERCIAL-TERMS.md), and [PRICING.md](./PRICING.md).
