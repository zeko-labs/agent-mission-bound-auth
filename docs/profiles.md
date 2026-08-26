# Protocol Profiles

MBA separates authorization security from settlement. Applications can adopt
mission-bound authorization without running private compute, trusting a TEE, or
submitting a transaction. Zeko settlement adds proof-backed release and public
auditability when the mission carries economic consequences.

## Configuration

```text
MISSION_AUTH_PROFILE=demo | portable | production
MISSION_SETTLEMENT_PROFILE=none | zeko
```

`production_strict` remains accepted as a legacy alias for the production auth
profile and strict verifier mode. Existing deployments that set
`MISSION_AUTH_PROFILE=production` without a settlement setting retain the
original `zeko` settlement default.

Conflicting runtime settings fail closed. In particular, `DEMO_MODE=true`
cannot run with a secure auth profile, and a demo profile cannot run under
`NODE_ENV=production`.

## Demo

```text
MISSION_AUTH_PROFILE=demo
MISSION_SETTLEMENT_PROFILE=none
DEMO_MODE=true
```

The tutorial sidecar supports deterministic digest holder proofs, mock x402 v2
authorizations, in-memory state, and proofs-disabled o1js simulation. These
artifacts exist for local implementation, fixtures, and conformance testing.
Secure profiles reject them.

Run the preserved demo:

```bash
npm start
npm run test:demo
npm run test:zeko:simulated
```

## Portable Authorization

```text
MISSION_AUTH_PROFILE=portable
MISSION_SETTLEMENT_PROFILE=none
DEMO_MODE=false
```

Portable mode provides production-grade authorization without a settlement
operator:

- verified OIDC/JWKS identity and signed enterprise attestations
- authority-signed mission approvals and capabilities
- browser or extension-held Ed25519 keys
- holder-signed, replay-resistant boundary events
- exact budget accounting and checkpoint ordering
- redacted traces, handoff receipts, and portable execution bundles

No Pallas holder key, domain-verifier key, x402 facilitator, Zeko deployer,
MissionRegistry, central compute partner, or TEE is required. The domain
application enforces checkpoints before its own side effects. A browser
extension can keep the holder key local and disclose only signed commitments.

Start from `.env.portable.example` and run:

```bash
npm run test:portable
npm run production:doctor
```

## Zeko Settlement

```text
MISSION_AUTH_PROFILE=production
MISSION_SETTLEMENT_PROFILE=zeko
DEMO_MODE=false
```

This profile adds:

- dual Ed25519 and Pallas holder binding
- mission-approved domain-verifier attestations
- real MissionCompliance proofs
- x402 v2 payment verification and settlement
- MissionRegistry approval, revocation, escrow, receipt, and nullifier state
- atomic beneficiary payout and protocol-fee release

The active deployment target is Zeko Ethereum Sepolia. MBA submits ordinary
o1js transactions to `https://sepolia.zeko.io/graphql`, signs with the
`testnet` domain required by that endpoint, and settles its zkApp escrow in
native 9-decimal sETH. Ethereum rollup batching and bridge finality are below
the MBA application boundary and are not runtime dependencies of this profile.

The domain verifier is not an MBA compute monopoly. It can be the merchant,
application, an independent verifier, a local prover, or a composed domain
circuit. MissionRegistry releases value only after the complete proof and
registry transition verifies.

Run the fast state-machine simulation and real proving separately:

```bash
npm run test:zkapp-trustless
npm run test:zkapp-trustless:proofs
```

## Compatibility

The original sidecar endpoints, digest fixtures, mock payment helper, and
proofs-disabled test path remain available only in the demo profile.

`zkapp/PrivateComputeAccess.ts` retains the original v0 contract and state
layout. Existing v0 deployments remain distinct from `MissionRegistry`.
Trustless settlement v1 requires a fresh MissionRegistry zkApp key and
deployment; the code does not alias an old contract name to new behavior.
