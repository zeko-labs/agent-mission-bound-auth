# MBA Zeko Programs

## MissionComplianceProgram

`MissionComplianceProgram.ts` proves that up to four holder-signed boundary
events:

- belong to one mission, capability, and policy
- are members of approved action and domain sets
- form one contiguous trace
- occur before mission expiry
- fit within the approved aggregate microusd budget
- carry a valid trusted domain-verifier signature over the dataset, domain
  proof, and output commitments
- bind the dataset, domain proof, output, payment context, receipt, beneficiary,
  payout, and protocol fee commitments

Private data and event details remain witnesses. The public statement contains
only commitments, roots, counters, the beneficiary, and settlement amounts.
The active network is Zeko Ethereum Sepolia, where those settlement amounts are
native 9-decimal sETH units. The v1 TypeScript field names retain `Nanomina`
only to preserve the circuit and verification-key identity.

`domainProofCommitment` binds domain-specific evidence. The circuit verifies a
mission-approved Pallas verifier attestation over that evidence and its output.
Receipt verification also executes the domain adapter against the disclosed
evidence.

## MissionRegistry

`MissionRegistry.ts` stores:

- mission authority public key
- protocol fee recipient
- one namespaced Merkle root for approvals, revocations, nullifiers, receipts,
  and escrows
- monotonic registry sequence

The authority anchors approvals and revocations with signatures separated by
registry address, operation, and sequence. Payers fund mission escrows.
`settleMission` verifies the compliance proof, approval membership, revocation
non-membership, unused nullifier, empty receipt slot, and active escrow. It then
consumes the nullifier, inserts the receipt, closes escrow, and atomically pays
the beneficiary and fee recipient. Expired active escrows can be refunded.

`PrivateComputeAccess.ts` is the frozen v0 implementation, including its
original class, receipt type, methods, and state layout. Existing v0 deployments
remain separate from `MissionRegistry`. New trustless settlement deployments
use the MissionRegistry verification key and require a fresh zkApp key. The
retired Mina-backed v0 address and transaction record are preserved in
`docs/legacy-private-compute-access-v0.md`.
