# Portable Receipt And Proof

`mission-bound-auth-receipt-v1` is the redacted audit envelope. It binds the
mission, signed capability artifact, auth and approval commitments, policy,
holder, trace, domain proof evidence and attestation, payment, nullifier, proof
artifact, Zeko public statement, anchor, and settlement lifecycle.

Public receipts must not contain OIDC tokens or subjects, prompts, raw data,
URLs, selectors, form values, credentials, payment secrets, or holder secrets.

## Proof Artifact

Production receipts carry `mba-mission-compliance-proof-v1`:

```json
{
  "version": "mba-mission-compliance-proof-v1",
  "proofSystem": "zeko-o1js-mission-compliance-v1",
  "circuitDigest": "...",
  "verificationKeyHash": "...",
  "publicStatement": {
    "missionIdHash": "...",
    "capabilityCommitment": "...",
    "receiptCommitment": "...",
    "nullifier": "...",
    "beneficiary": "B62...",
    "payoutNanomina": "...",
    "protocolFeeNanomina": "..."
  },
  "proof": {
    "publicInput": ["..."],
    "publicOutput": [],
    "maxProofsVerified": 0,
    "proof": "..."
  },
  "artifactHash": "..."
}
```

The complete statement is defined by
`schemas/mission-compliance-proof.schema.json`.

The v1 proof statement retains the historical field names
`payoutNanomina` and `protocolFeeNanomina` so existing circuit and verification
key artifacts remain stable. On Zeko Ethereum Sepolia those integers are
9-decimal native sETH units. Signed capabilities and registry anchors expose
the equivalent `payoutNativeUnits` and `protocolFeeNativeUnits` aliases.

The verifier checks artifact integrity, trusted key hash, circuit digest,
serialized proof validity, and equality between decoded proof input and the
named public statement. `statementHash` in the receipt hashes that same named
statement.

The signed capability is verified against the mission-authority JWKS. Its Zeko
binding must match the proof statement field for field. The receipt's
settlement nullifier is the Field nullifier consumed by MissionRegistry; the
off-chain capability nullifier remains a distinct capability lifecycle value.

The receipt's `domainProof.evidence` hashes to `domainProofCommitment`.
`domainProof.attestation` carries a Pallas signature verified by the circuit
against `domainVerifierKeyCommitment`. The production verifier then executes
the configured domain adapter against the evidence.

## Zeko Anchor

`mba-zeko-registry-anchor-v2` links the proof artifact and public settlement
fields to a MissionRegistry transaction, sequence, and resulting root.
It also identifies the Zeko Ethereum Sepolia network, `testnet` signing domain,
and native sETH asset. Verification confirms Zeko transaction inclusion and
registry state. Historical anchors require actions/events evidence from a
transaction-capable Zeko endpoint.

## Settlement Rule

`receipt_created`, `proof_prepared`, and `anchor_prepared` are preparation
states. `settlement_release_allowed` and `settled` are final states, but their
labels are not authority by themselves.

`verifySettlementOnZeko` performs domain-evidence, proof, and live-chain
verification before combining the result into a release decision.
`verifySettlementState` is the lower-level decision combiner.
`allowUnverifiedDemoEvidence` exists only for deterministic local fixtures and
must never be enabled in production.
