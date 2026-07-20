# Portable Receipt Format

The portable receipt is the artifact that lets a third party verify mission
work without trusting the demo app or seeing private data.

Receipts use `mission-bound-auth-receipt-v1` and are intentionally redacted.
They include commitments and hashes, not raw prompts, credentials, selectors,
page text, payment secrets, private vault values, or underlying dataset rows.

## Required Verifier Questions

A verifier should be able to answer:

- Was this receipt created under a mission-bound capability?
- Does the policy hash match the approved task boundary?
- Did the holder runtime produce a trace commitment?
- Is the payment context bound to the same receipt?
- Is the receipt nullifier unique for settlement?
- Is the receipt/root anchor present for production settlement?

## Shape

```json
{
  "schema": "mission-bound-auth-receipt-v1",
  "receiptId": "receipt_...",
  "receiptHash": "...",
  "mission": {
    "missionIdHash": "...",
    "capabilityHash": "...",
    "issuer": "agent-mission-bound-auth",
    "audience": "mission-verifier"
  },
  "policy": {
    "policyHash": "...",
    "allowedDomainsHash": "...",
    "allowedActionsHash": "...",
    "maxSpendCommitment": "...",
    "paymentRailsHash": "..."
  },
  "holder": {
    "keyThumbprint": "...",
    "proofScheme": "ed25519-holder-proof-v1"
  },
  "trace": {
    "eventCount": 3,
    "traceHash": "...",
    "latestEventHash": "..."
  },
  "payment": {
    "paymentCommitment": "...",
    "rail": "zeko",
    "amountCommitment": "...",
    "paymentContextDigest": "..."
  },
  "proof": {
    "statementKind": "mission-bound-trace-compliance-v1",
    "statementHash": "...",
    "proofSystem": "signed-commitment-transition",
    "verificationKeyHash": null
  },
  "nullifier": "...",
  "registryRoot": "...",
  "settlementState": "settlement_release_allowed",
  "anchor": {
    "registry": "zeko:testnet",
    "payloadDigest": "...",
    "txHash": "...",
    "sequence": 7,
    "nullifier": "..."
  },
  "exportedAt": "2026-07-05T00:00:00.000Z"
}
```

## Anchor Rule

A receipt can be in `anchor_prepared` while it is waiting to be finalized. A
production-settled receipt must include anchor evidence. The verifier rejects
`settlement_release_allowed` or `settled` receipts that lack an anchor unless
the caller explicitly allows pre-final receipts.

## Holder Proof Rule

Receipts point to the trace commitment and holder proof scheme. Local examples
may use `digest-holder-proof-v1`, but production traces should use
`ed25519-holder-proof-v1` or another public-key/ZK-friendly holder proof scheme.
The verifier rejects digest holder proofs in production mode.

## Production Strict Rule

`production_strict` receipt verification requires:

- strong holder proof scheme evidence, currently `ed25519-holder-proof-v1`
- proof statement hash and proof system metadata
- payment context digest
- nullifier
- Zeko anchor evidence

Use this mode for production-final browser/helper-agent receipts and settlement
release checks.
