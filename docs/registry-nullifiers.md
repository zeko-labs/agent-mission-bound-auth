# Append-Only Registry And Nullifiers

The production registry is an append-only audit log for mission approval and
receipt roots. It exists so settlement can be checked independently from the
application that performed the work.

## Anchor Fields

```ts
type MissionAnchor = {
  registryVersion: "mba-registry-v1";
  sequence: number;
  missionIdHash: string;
  capabilityHash: string;
  statementHash: string;
  payloadDigest: string;
  receiptIdHash: string;
  nullifier: string;
  previousRoot: string;
  newRoot: string;
  anchoredAt: string;
  networkId: string;
  registryAddress: string | null;
  txHash: string | null;
  proofHash: string;
  anchorId: string;
};
```

The verifier treats `sequence`, `previousRoot`, `newRoot`, and `nullifier` as
registry-derived or verifier-checkable fields. They are not trusted merely
because a client included them in JSON.

`buildRegistryAnchorFromReceipt` accepts a portable receipt, Zeko proof
artifact, relayer response, zkApp/registry address, transaction hash, and root
inputs, then returns the canonical `mba-registry-v1` anchor plus a verifier
result. This keeps relayer integrations deterministic and easy to audit.

## Nullifier Rule

Every settlement-capable receipt carries a nullifier derived from the mission
capability and settlement release condition. A registry or settlement verifier
must reject the second use of the same nullifier as `duplicate_payment`.

## Settlement Lifecycle

Settlement release follows this state path:

```text
receipt_created -> proof_prepared -> proof_verified -> anchor_prepared
anchor_prepared -> anchored -> settlement_release_allowed -> settled
```

Release decisions are valid only once the receipt is anchored and reaches
`settlement_release_allowed`. Verifiers reject duplicate nullifiers, expired
authorization, disallowed rails, unsupported state transitions, and release
attempts from earlier states.
