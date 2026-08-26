# Architecture

MBA is layered. Portable authorization ends after application enforcement and
receipt export; the settlement profile continues through x402 and Zeko.

```mermaid
sequenceDiagram
  participant Principal
  participant IdP as Auth0 / Okta / OIDC
  participant MBA as MBA Sidecar
  participant Holder as Agent Holder
  participant App as Domain App
  participant X402 as x402 Facilitator
  participant Zeko as MissionRegistry on Zeko Ethereum Sepolia

  Principal->>IdP: Authenticate
  IdP-->>MBA: Authorization code + ID token
  MBA->>MBA: Verify PKCE, nonce, JWKS, issuer, audience, expiry
  MBA-->>Holder: Signed identity attestation and passport
  Holder->>MBA: Propose mission
  MBA-->>Holder: Signed approval and holder-bound capability
  Holder->>App: Holder-signed boundary events
  App-->>Holder: Enforcement receipt / redacted trace
  rect rgb(235, 245, 255)
  Note over MBA,Zeko: Zeko settlement profile
  MBA->>Zeko: Anchor approval commitment
  App->>X402: Verify x402 v2 payment authorization
  App->>App: Verify work and sign proof/output commitments
  Holder->>Holder: Prove mission compliance privately
  Holder->>Zeko: Settle proof against funded escrow
  Zeko->>Zeko: Consume nullifier and record receipt
  Zeko-->>Holder: Atomic sETH beneficiary payout and protocol fee
  end
```

## Proof And Registry

```mermaid
flowchart LR
  I["Verified OIDC identity"] --> C["Signed mission capability"]
  C --> E["Holder-signed boundary events"]
  E --> P["MissionCompliance proof"]
  D["Domain proof commitment"] --> P
  V["Trusted domain-verifier signature"] --> P
  X["x402 payment context"] --> P
  P --> R["MissionRegistry"]
  A["Anchored approval"] --> R
  F["Funded escrow"] --> R
  R --> N["Nullifier consumed"]
  R --> Q["Receipt recorded"]
  R --> S["Payout + fee"]
```

Domain apps own work semantics and domain proof generation. MBA pins their
approved Pallas verifier keys, proves the verifier signature inside
MissionCompliance, independently verifies disclosed evidence during receipt
verification, and owns authority, policy proof, replay resistance, receipt
binding, and Zeko settlement. The private-compute harness is one adapter, not
the protocol boundary.

## Profile Boundaries

```mermaid
flowchart LR
  D["Demo: digest fixtures + mock x402 + simulated proofs"]
  P["Portable: OIDC + signed capability + Ed25519 events"]
  A["Application or browser-extension enforcement"]
  Z["Zeko settlement: domain proof + x402 + MissionRegistry"]
  O["Conditional payout + public receipt anchor"]

  D --> P
  P --> A
  A --> Z
  Z --> O
```

Portable mode has no central compute, TEE, facilitator, or chain runtime
dependency. Zeko settlement is a stronger continuation for proof-backed
commerce, not a prerequisite for mission-bound browser authorization.
