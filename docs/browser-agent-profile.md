# Browser Agent Profile

The browser profile is the MBA vocabulary for browser-held missions. It lets a
browser runner, extension, helper agent, or local automation runtime prove what
it was allowed to do without leaking the raw browsing session.

## Artifacts

`mba-browser-mission-profile-v1` binds:

- mission, capability, policy, and holder key commitments
- runner/runtime identity
- tab and session commitments
- current URL and domain hashes
- page-state class, checkout checkpoint, safe next-action score, and stop reason

`mba-redacted-trace-v1` exports only public hashes and canonical action
vocabulary. It excludes raw URLs, selectors, form text, addresses, card labels,
emails, page text, and HTML. Owner-only trace material is represented by a
commitment.

`mba-human-handoff-v1` proves the agent stopped before crossing a policy or
human-approval boundary. Standard stop reasons include `login_required`,
`payment_required`, `final_approval_required`, `policy_conflict`,
`budget_exceeded`, `uncertain`, `domain_not_allowed`, and
`mission_capability_expired`.

`mba-execution-bundle-v1` is the portable browser execution export. It can carry
the capability, policy, browser profile, redacted trace, handoff receipt,
portable receipt, Zeko registry anchor, settlement state, verifier links, and an
owner-only trace commitment.

## Production Strict

Browser agents should run short-lived capabilities and renew them instead of
keeping long authority windows open. Production-strict verification rejects
digest holder proofs and compatibility holder proofs. It requires a strong
holder proof, expiry, idempotency key, holder key commitment, receipt proof
statement evidence, and Zeko anchor evidence for finalized receipt exports.

Compatibility holder proofs such as `browser-helper-ed25519-pop-v1` are for
staging migrations only. They are represented in the protocol so early
integrations can be tested honestly, but `production_strict` rejects them.

## Browser Helper Flow

1. Pair or register the helper agent and bind a holder public key.
2. Issue a mission-bound capability with narrow browser actions and a short
   expiry.
3. Build a browser mission profile for the current session and tab commitment.
4. Sign each boundary event with `ed25519-holder-proof-v1`.
5. Export a redacted trace and handoff receipt if the run stops before login,
   payment, final submit, or a policy-conflict boundary.
6. Build the portable receipt, anchor the receipt/root on Zeko, and export an
   execution bundle.
7. Verify with `mba verify bundle execution-bundle.json`.
