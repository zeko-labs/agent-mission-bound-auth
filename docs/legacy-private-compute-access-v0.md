# PrivateComputeAccess v0

`zkapp/PrivateComputeAccess.ts` is the original private-compute receipt anchor.
It is retained as a frozen compatibility contract and is not an alias for
`MissionRegistry`.

## Retired Mina-Backed Testnet Deployment

```text
network: zeko:testnet
zkApp: B62qpBXMbrKVJwcS9wQN7SpFb6jkrXn2xrntCoM6D461qL2sYZarPHi
beneficiary: B62qjxFhBZ2W1jzMyAppBkD22gGN66gTRYpX9AyaC4Kwga1kbC8zLBN
deployer: B62qqpyJPDGci2uxpapnXQmrFr77b47wRx1v2GDRnAHMUFJFjJv4YPb
deploy transaction: 5JvJ46fMoxm63tudgdtpETYzX9hXWgm2Phmxxe4nJkY36oS6ZTUj
configure transaction: 5JtxfzS5rqMa2vBDHpmmpLN1tiEo52zFsy1BPugPU4mMqArVGoBX
deployed: 2026-04-30T22:10:50Z
```

The v0 state consists of dataset, authorization, and receipt roots plus one
configured beneficiary. It records commitments but does not verify the
MissionCompliance proof, enforce registry nullifiers, manage mission escrow, or
release beneficiary and protocol-fee payouts atomically.

Existing v0 users can continue verifying this contract and its historical
transactions against the retired network records. It is not an active MBA
deployment target. New trustless settlement deployments use
`zkapp/MissionRegistry.ts` because its state layout and verification key are
intentionally different. A fresh chain deployment may reuse a prior B62 public
identity when the key holder chooses, but it always begins with a new v1 state
root and does not inherit v0 state.

The former `data/*-anchor-state.json` files were local mutable indexes with
pending client state, not canonical chain evidence. They are no longer tracked.
