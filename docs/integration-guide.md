# Integrating ZK Mission Auth

This guide shows how a domain app plugs into the protocol. The local
private-compute UI is only a tutorial harness; production apps should integrate
at the protocol endpoints below. Choose
[portable authorization or Zeko settlement](./profiles.md) before provisioning
keys.

## 1. Discover The Control Plane

```js
import { ZkMissionAuthClient, verifyMissionBundle } from "agent-mission-bound-auth/sdk";

const auth = new ZkMissionAuthClient({ baseUrl: "https://auth.example" });
const discovery = await auth.discover();
```

## 2. Ask For A Mission Approval

```js
const { agentPassport } = await auth.createAgentPassport({
  agentId: "agent-research-ops-001",
  organization: "Northstar Bio",
  identityAttestation,
  holderKeyCommitment
});

const { mission } = await auth.proposeMission({
  agentId: agentPassport.agentId,
  datasetId: "clinical-failures-q1",
  operation: "risk-summary",
  task: "Summarize the private clinical risk.",
  allowedDomains: ["compute.example"],
  allowedTools: ["private_compute.run", "your_app.side_effect"],
  allowedScopes: ["compute:clinical", "dataset:clinical-failures-q1"],
  allowedRails: []
});

const { approval } = await auth.approveMission({
  missionId: mission.missionId,
  approverId: "policy-engine@example.com"
});
```

## 3. Verify Before Side Effects

```js
const check = await auth.verifyCheckpoint({
  checkpoint: "before_external_side_effect",
  approval,
  context: {
    agentId: mission.agentId,
    datasetId: mission.datasetId,
    operation: mission.operation,
    action: "your_app.side_effect",
    missionExecutionId: "exec-123",
    idempotencyKey: "your-app-action-123"
  }
});

if (!check.ok) throw new Error("not authorized");
```

`verifyCheckpoint` is stateless. If your service is authorized to mutate mission
authority replay, ordering, budget, and enforcement-log state, call
`enforceCheckpoint` with the production bearer token instead:

```js
await auth.enforceCheckpoint({
  checkpoint: "before_external_side_effect",
  approval,
  context: check.event.context
}, process.env.MISSION_APPROVAL_BEARER_TOKEN);
```

## 4. Export A Portable Bundle

```js
const { bundle } = await auth.exportBundle({
  agentPassport,
  mission,
  approval,
  receipt: yourDomainReceipt
});
```

Store `bundle.bundleHash` with your domain audit record.

Verify the bundle offline with the mission authority JWKS:

```js
const jwks = await auth.jwks();
verifyMissionBundle(bundle, jwks);
```

This is the complete portable authorization flow. A browser extension can own
the Ed25519 key and produce the boundary events locally; the application only
needs the signed artifacts and mission-authority JWKS.

## 5. Add Zeko Settlement

For the Zeko settlement profile, add the holder Pallas key to the passport and
approval, prepare the authority-signed Zeko capability binding, obtain the approved
domain-verifier attestation, compile the MissionCompliance inputs, and produce
the proof. Then use the registry lifecycle:

```bash
npm run zkapp:anchor-approval
npm run zkapp:fund-mission
npm run zkapp:settle-mission
npm run zkapp:get-state
```

Production-final receipts include the concrete proof artifact and canonical
MissionRegistry anchor. The settlement verifier checks the trusted domain
attestation, domain evidence, proof, transaction, root, sequence, and
nullifier.

## 6. Run A Conformance Check

Local primitives:

```bash
npm run test:conformance
```

Against a running implementation:

```bash
CONFORMANCE_BASE_URL=https://auth.example npm run test:conformance:remote
```

The remote conformance check exercises discovery, JWKS, passport issuance, mission proposal, approval, checkpoint verification, bundle export, schema validation, and offline JWS verification.

## 7. Start From The External App Starter

The reference external app is in `apps/external-starter`.

It is deliberately not private compute. It verifies a mission checkpoint before a simulated email side effect, which is the pattern other apps should copy.
