# Zeko Ethereum Sepolia

MBA's active settlement deployment runs as an ordinary o1js zkApp on Zeko
Ethereum Sepolia. The MBA application does not submit Ethereum batches, call an
Ethereum RPC, or operate bridge infrastructure. Zeko supplies those network
services below the zkApp execution boundary.

## Network Profile

```env
ZEKO_GRAPHQL=https://sepolia.zeko.io/graphql
ZEKO_ARCHIVE=https://sepolia.zeko.io/graphql
ZEKO_PROTOCOL_NETWORK_ID=zeko:sepolia
ZEKO_NETWORK_ID=testnet
ZEKO_NETWORK_NAME=Zeko Ethereum Sepolia
ZEKO_NATIVE_ASSET=sETH
ZEKO_NATIVE_DECIMALS=9
ZEKO_NATIVE_TOKEN_ID=wSHV2S4qX9jFsLjQo8r1BsMLH2ZRKsZx6EJd1sbozGPieEC4Jf
TX_FEE=200000
```

The three machine identifiers have different purposes:

- MBA capabilities, receipts, registry anchors, and x402 rail metadata use
  `protocolNetworkId: zeko:sepolia`.
- GraphQL reports `networkID: zeko:testnet`.
- o1js and Auro sign transactions with `networkId: testnet`.

`zeko:sepolia` is MBA's canonical protocol-routing identifier. It is not an
o1js signing domain and is not asserted to be Zeko's GraphQL network ID.
User-facing applications display `Zeko Ethereum Sepolia`.

Passing `zeko:testnet` or `zeko` to `Mina.Network({ networkId })` produces the
wrong signature domain. `Mina.Network` is the o1js API name; using it does not
mean MBA is deployed on Mina.

New capability bindings and anchors use v3 and carry all three identifiers.
Verification remains compatible with v2 artifacts that used `zeko:testnet` as
their single application-facing network value. This metadata split does not
change the MissionRegistry verification key, address, state, or transactions,
so it does not require a contract redeployment.

## Canonical MissionRegistry

The current public Sepolia deployment is recorded in
`data/deployment.mission-registry.zeko-sepolia.json`:

- Registry: `B62qikuceF52NVPb8VAVSaRoCRMusFz38pLLENjvLaUuLiDnULAVohe`
- Mission authority: `B62qic83mhTzuGWCMpq183bZxqFtMbMDBbFRxQBCXTzBUKCd9B7aSdV`
- Protocol fee recipient: `B62qqsTbSjdgqzhUojPZRrWYmmf6BVsRrjwjuKsHpuaeaoob8YsDuNi`

The acceptance transaction anchored a signed approval, advanced the registry
to sequence `1`, and was independently read back from the sequencer.

The public endpoint currently serves account state and the actions/events
queries used by MBA. A separate transaction indexer can be configured later if
an operator needs wallet history or transaction recovery beyond those queries.

## Native Asset

sETH is the native gas and escrow asset. All MBA zkApp transfers use the native
`AccountUpdate.send` path with 9-decimal integer base units. No fungible-token
contract is involved. The frozen v1 circuit names its amount fields
`payoutNanomina` and `protocolFeeNanomina`; they carry sETH base units on this
deployment. Public capability and anchor artifacts also expose the clearer
`payoutNativeUnits` and `protocolFeeNativeUnits` aliases.

Query live network constants before deployment:

```bash
npm run zeko:live-check
```

## Deployment

Use a fresh registry key, authority key, and Sepolia-scoped witness index. Keep
all private keys in ignored local files or a secret manager.

```bash
npm run zkapp:generate-keys
npm run zkapp:deploy
npm run zkapp:get-state
```

`zkapp:deploy` verifies that the deployer private key matches an optional
`DEPLOYER_PUBLIC_KEY`, checks the funded account, deploys and configures
`MissionRegistry`, waits for both transactions, and writes public deployment
metadata to `data/deployment.mission-registry.zeko-sepolia.json`.

The local Merkle witness index defaults to
`data/mission-registry-state.zeko-sepolia.json`. Never reuse the retired
Mina-backed registry state or keys.

## Acceptance Gate

A Sepolia migration is complete only when all of these pass:

1. The live endpoint reports the expected network and signing domain.
2. The deployer public key derives from the configured private key and is funded.
3. The new MissionRegistry account is visible at the live endpoint.
4. Authority key, fee recipient, empty root, and sequence zero match deployment.
5. A signed approval transition advances the root and sequence.
6. Local CI and the Zeko trustless settlement simulation pass.
