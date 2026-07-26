# Helper Agent Starter Contract

Custom browser/helper agents should implement this minimal contract when they
integrate with MBA.

## Required Steps

1. `pair/register`: create or load a runtime identity and Ed25519 holder key.
2. `bind holder key`: send the public JWK thumbprint to the mission authority.
3. `poll mission`: fetch mission details and capability constraints.
4. `claim mission`: commit to a mission execution id and idempotency namespace.
5. `sign checkpoint`: emit `mission-bound-boundary-event-v1` with
   `ed25519-holder-proof-v1`.
6. `fulfill`: perform only approved browser or app actions.
7. `handoff`: stop and emit `mba-human-handoff-v1` before login, payment, final
   submit, uncertainty, policy conflict, or budget breach.
8. `export`: produce `mba-execution-bundle-v1` with a redacted trace, receipt,
   Zeko anchor, and settlement state.

## Security Requirements

- Never reuse holder keys across organizations unless the mission authority
  explicitly scopes them that way.
- Never sign a boundary event that omits `idempotencyKey`, `expiresAt`, or the
  previous event hash for production browser flows.
- Never export raw URLs, selectors, form text, page text, addresses, email
  values, or payment labels in public artifacts.
- Never release credits, x402 funds, or settlement until the receipt is
  anchored and the settlement lifecycle reaches `settlement_release_allowed`.

See `examples/helper-agent-starter.mjs` for a small reference adapter.
