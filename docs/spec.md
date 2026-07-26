# ZK Mission Authorization Protocol 0.1

## Purpose

Agent Mission-Bound Auth is a task-bound control protocol for delegated and autonomous agents.

It answers:

> Is this exact agent, representing this exact principal, approved to perform this exact action, against this exact resource, right now?

The protocol combines enterprise identity, task-bound approval, x402 payment, checkpoint enforcement, and Zeko anchoring.

## Actors

- **Agent**: autonomous or delegated software actor.
- **Represented principal**: user, organization, or service the agent acts for.
- **Mission authority**: service that issues agent passports and mission approvals.
- **Approver**: human, policy engine, IdP, or governance system approving a mission.
- **Domain app**: application performing the actual work or side effect.
- **Verifier**: party checking passports, approvals, bundles, receipts, or Zeko roots.

## Discovery

Mission authorities publish:

```text
GET /.well-known/agent-authorization.json
GET /.well-known/mission-authority-jwks.json
```

The first document describes protocol endpoints and capabilities. The second publishes public signing keys for offline verification.

## Agent Passport

`agent-passport-v1` identifies:

- `agentId`
- `agentIdentifier`
- represented principal
- vouching parties
- agent key binding
- mission-authority JWS

The passport is portable and can be verified offline.

## Mission

`mission-bound-agent-auth-v1` is a task-bound scope object.

It defines:

- agent
- represented principal
- natural-language task
- dataset/resource
- operation
- allowed tools
- allowed OAuth/resource scopes
- allowed payment rails
- spend and data-egress constraints
- required checkpoints
- expiry

## Capability

`mission-bound-capability-v1` is the hardened authority object used by
portable receipts and settlement. It explicitly binds:

- `capabilityId`
- `jti`
- `nullifierSeed`
- represented principal hash
- agent/runtime id
- holder key commitment
- mission id hash
- allowed domains/actions
- data scopes
- payment rails
- max spend
- expiry
- settlement release condition

The capability hash is the authority commitment downstream receipts and
registry anchors reference.

### Capability Renewal

`mission-bound-capability-renewal-v1` renews short-lived capabilities without
widening authority. A valid renewal keeps the same mission, holder key,
principal, agent, issuer, and audience; references the previous capability
hash; uses a fresh `jti` and nullifier; increments the renewal counter; and
keeps domains, actions, data scopes, payment rails, and spend limit the same or
narrower.

## Approval

`mission-approval-v1` binds an approver to a mission.

It includes a mission snapshot so a domain app can verify the approval without querying the original server. It is signed as ES256 JWS and may include a Zeko anchor reference.

Production mission authorities require an authority bearer token for passport,
mission proposal, approval, and revocation endpoints. Local tutorial mode keeps
those endpoints open for demonstration.

## Checkpoints

Recommended checkpoints:

- `before_payment_offer`
- `before_private_compute`
- `before_external_side_effect`
- `after_receipt`

Domain apps call the stateless verifier:

```text
POST /api/mission/verify-checkpoint
```

or verify the approval offline using the JWKS and enforce equivalent policy locally.

Mission authorities or trusted domain services call the stateful enforcement
endpoint:

```text
POST /api/mission/enforce-checkpoint
```

In production, stateful enforcement requires the authority bearer token and
durable state. Its checkpoint context must include a `missionExecutionId`.
Compute and side-effect checkpoints must also include an `idempotencyKey`,
`paymentId`, or `sideEffectId` so the authority can reject replay. When
`spendUsd` or `amountUsd` is present, the authority applies the mission budget
counter before accepting the checkpoint.

## Browser Missions

Browser/helper-agent workflows use four additional portable objects:

- `mba-browser-mission-profile-v1`: holder/runtime/session/tab commitments,
  current URL/domain hashes, page-state class, next-action score, stop reason,
  and checkout checkpoint.
- `mba-redacted-trace-v1`: public hash-only trace summary with no raw URLs,
  selectors, page text, form values, addresses, emails, or payment labels.
- `mba-human-handoff-v1`: proof that the agent stopped before login, payment,
  final submit, uncertainty, budget breach, or policy conflict.
- `mba-execution-bundle-v1`: portable export containing capability, policy,
  browser profile, redacted trace, handoff receipt, receipt, Zeko anchor,
  settlement state, verifier links, and owner-only trace commitment.

Browser missions should use `production_strict` verification for production
settlement paths.

## Bundle

`zk-mission-bundle-v1` is the portable handoff object containing:

- agent passport
- mission
- approval
- auth commitments
- payment receipt
- domain receipt
- Zeko references

The `bundleHash` is the canonical audit handle.

## Zeko Anchoring

Zeko roots provide independent auditability:

- `authRoot`: mission approval / authorization commitments
- `receiptRoot`: execution receipt commitments
- `datasetRoot`: optional committed dataset registry

Production deployments should anchor both:

```text
Before action: approval commitment
After action: execution receipt commitment
```

## Portable Verification

Portable verifiers can independently check:

- capability hash and nullifier construction
- renewal proof preserves mission and narrows authority
- boundary event holder-proof binding
- trace hash chain continuity
- browser profile and redacted trace privacy
- receipt hash, policy hash, payment context, and settlement state
- registry anchor payload digest and receipt linkage

See [receipt format](./receipt-format.md), [boundary events](./boundary-events.md),
[registry/nullifiers](./registry-nullifiers.md), and
[public verifier CLI](./verifier-cli.md).

## Non-Goals

The protocol does not define domain-specific work. Apps still own their own private compute, trading, procurement, email, code execution, or payment semantics.

The included private-compute UI is a tutorial harness, not part of the protocol.
