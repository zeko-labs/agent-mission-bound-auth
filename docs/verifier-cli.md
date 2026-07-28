# Public Verifier CLI

The repository ships a small verifier CLI so a third party can inspect protocol
artifacts without running the demo harness.

```bash
npm run mba -- verify receipt receipt.json
npm run mba -- verify receipt --production-strict receipt.json
npm run mba -- verify bundle execution-bundle.json
npm run mba -- verify trace trace.json
npm run mba -- verify anchor receipt.json anchor.json
npm run mba -- verify settlement receipt.json anchor.json \
  --verification-key verification-key.json \
  --authority-jwks authority-jwks.json \
  --domain-verifier domain-verifier.mjs \
  --graphql https://testnet.zeko.io/graphql \
  --registry B62...
```

The domain-verifier module exports `verifyDomainProof` or a default async
function. It receives the disclosed domain proof evidence and the proof-bound
receipt context, and returns `true` or `{ valid: true }`. Production settlement
fails closed when the module is absent, the Pallas attestation is invalid, or
the verifier rejects the evidence.

The authority JWKS verifies the signed capability carried by the receipt. The
verifier then matches that capability's identity, holder, policy, allowlist,
domain-verifier, escrow, and Zeko commitments to the proof statement. The
receipt settlement nullifier must be the same Field nullifier consumed on
Zeko.

The output is intentionally boring JSON:

```json
{
  "valid": true,
  "capability": "valid",
  "holderProofs": "valid",
  "traceChain": "valid",
  "policy": "valid",
  "paymentBinding": "valid",
  "anchor": "valid",
  "settlement": "release_allowed"
}
```

## Library APIs

Applications can import the same verification primitives from the SDK:

```js
import {
  verifyCapability,
  verifyCapabilityRenewal,
  verifyExecutionBundle,
  verifyProductionStrictReceipt,
  verifyReceiptDomainProof,
  verifyTraceChain,
  verifyReceipt,
  verifyAnchorPayload,
  verifySettlementTransitionChain,
  verifySettlementState
} from "agent-mission-bound-auth/sdk";
```
