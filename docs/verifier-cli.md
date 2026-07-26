# Public Verifier CLI

The repository ships a small verifier CLI so a third party can inspect protocol
artifacts without running the demo harness.

```bash
npm run mba -- verify receipt receipt.json
npm run mba -- verify receipt --production-strict receipt.json
npm run mba -- verify bundle execution-bundle.json
npm run mba -- verify trace trace.json
npm run mba -- verify anchor receipt.json anchor.json
npm run mba -- verify settlement receipt.json --registry settlement.json
```

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
  verifyTraceChain,
  verifyReceipt,
  verifyAnchorPayload,
  verifySettlementTransitionChain,
  verifySettlementState
} from "agent-mission-bound-auth/sdk";
```
