# Security Policy

## Reporting

Do not open a public issue for a suspected vulnerability.

Report vulnerabilities privately to `security@zeko.io` with:

- affected commit and component
- reproduction steps or proof of concept
- expected impact
- suggested remediation, when available

Do not include production credentials, private keys, private datasets, or
unredacted customer artifacts.

## Supported Version

Security fixes target the current `main` branch until versioned releases are
published. Pin production deployments to a reviewed commit and verification-key
hash.

## Security Boundaries

MBA provides mission-scoped authorization, holder participation, policy-bound
trace proof, replay resistance, proof-bound receipts, Zeko registry evidence,
and conditional settlement.

MBA does not prove that an LLM reasoned correctly, a merchant fulfilled an
order, a website reported truthful state, or a domain verifier implementation
is sound. It proves that the approved verifier attested the committed evidence
and output and that the configured adapter accepted the disclosed evidence.

## Production Requirements

- Pin OIDC issuer, audience, algorithms, and JWKS trust roots.
- Map IdP subjects to agents server-side.
- Require signed enterprise identity attestations for passports and approvals.
- Protect mission authority, Zeko authority, payer, and zkApp keys with
  isolated KMS/HSM or wallet controls.
- Pin the MissionCompliance verification-key hash and circuit digest.
- Pin domain-verifier Pallas keys and require the domain-specific evidence
  verifier before settlement is accepted.
- Reject demo holder proofs and mock x402 payments.
- Use transactional durable stores for replay, budgets, revocations, and Merkle
  witnesses; serialize registry writers.
- Require cryptographic proof verification and chain-backed Zeko verification
  before settlement release.
- Monitor nullifier duplication, root divergence, failed proof rates, unusual
  approval issuance, and authority-key changes.
