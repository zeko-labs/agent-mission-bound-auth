# MissionRegistry And Nullifiers

MBA production settlement uses `MissionRegistry`, not a client-computed rolling
hash.

The contract stores one namespaced `MerkleMap` root. Keys are Poseidon hashes
with distinct namespaces for:

```text
approval     capability -> approval commitment
revocation   capability -> revoked flag
nullifier    nullifier -> spent flag
receipt      receipt commitment -> settlement leaf
escrow       mission + nonce -> escrow status and terms
```

A settlement proof is accepted only if the approval is present, revocation is
absent, nullifier and receipt are unused, and escrow is active. Nullifier,
receipt, and escrow changes occur in one transaction, so duplicate payout
cannot race a successful settlement.

Every root-changing approval, revocation, funding, settlement, or refund
transition advances the registry sequence.

Authority signatures include the operation namespace, registry address,
current sequence, and target commitments. A signature for one deployment or
sequence cannot authorize another.

## Anchor Evidence

`mba-zeko-registry-anchor-v1` binds:

- registry address, transaction hash, sequence, and resulting registry root
- mission, capability, approval, receipt, nullifier, and payment commitments
- beneficiary, payout, protocol fee, and proof artifact hash

Portable verification first checks artifact integrity and proof binding, then
verifies the o1js proof against a trusted key, confirms the transaction is
included, and checks the registry state. Historical anchors require an
archive-backed event verifier because the current root may have advanced.

## Local Witness Index

The Zeko scripts rebuild witnesses from
`MISSION_REGISTRY_STATE_PATH`. Writes are atomic, but a production operator
must serialize writers and store the index in transactional,
access-controlled, backed-up storage. Root mismatch against Zeko fails closed.
