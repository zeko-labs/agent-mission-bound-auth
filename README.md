# Agent Mission-Bound Auth

Protocol sidecar and source-available reference implementation for delegated
and autonomous agents.

It binds enterprise identity to a specific mission, signs the approval, enforces checkpoints before side effects, links x402 payment context, and emits portable receipts that can be independently verified and anchored on Zeko.

The included private-compute UI is only a local tutorial harness. The protocol is the product.

## Network Profile

This demo is testnet-first by default. For mainnet, use a separate environment profile with official mainnet endpoints, a freshly deployed private-compute zkApp, fresh deployer/beneficiary keys, and production custody controls. Do not reuse the bundled testnet zkApp address or local tutorial values on mainnet. See [Zeko Mainnet Readiness](../docs/zeko-mainnet-readiness.md).

## What It Provides

- Real OIDC login through Auth0, Okta, or any configured OIDC provider.
- Agent passports that say who the agent is, who it represents, and who vouches for it.
- Mission-bound approvals with signed snapshots of task, tools, scopes, rails, budget, and expiry.
- Stateless checkpoint verification for external apps and bearer-gated checkpoint enforcement for mission-authority state.
- Portable `zk-mission-bundle-v1` exports with offline JWKS verification.
- Portable `mission-bound-auth-receipt-v1` exports with trace, payment, policy, nullifier, and anchor linkage.
- Browser mission profiles, redacted trace exports, human handoff receipts, and portable execution bundles for browser/helper agents.
- Capability renewal for short-lived mission authority without widening holder, mission, domain, action, rail, or spend scope.
- `production_strict` verifier mode for strong holder proof, expiry, idempotency, receipt proof evidence, and Zeko anchor enforcement.
- Public `mba` verifier CLI for receipts, traces, anchors, and settlement state.
- x402 rail metadata for Zeko, Ethereum, Base, Arc preview, and Tempo preview.
- Zeko approval/receipt anchoring scripts for production on-chain audit roots.
- Production profile that disables demo minting, pins OIDC trust roots, requires authority tokens, rejects mock settlement, and enforces durable replay/budget checks.

## Repository Layout

```text
packages/protocol      core protocol objects, OIDC, missions, x402 rails, digests
packages/sdk           client and offline verification helpers
apps/harness           local tutorial sidecar and private-compute example
apps/external-starter  minimal external app that verifies mission checkpoints
schemas                portable object schemas
scripts                smoke, conformance, OAuth, and Zeko anchoring scripts
zkapp                  Zeko zkApp source
```

## Run Locally

```bash
npm install
npm start
```

Open:

```text
http://127.0.0.1:8787
```

## Configure Identity Providers

Local env lives in `.env.local` and must not be committed.

Auth0:

```bash
AUTH0_ISSUER=https://your-tenant.us.auth0.com/
AUTH0_DOMAIN=your-tenant.us.auth0.com
AUTH0_CLIENT_ID=...
AUTH0_CLIENT_SECRET=...
```

Auth0 SPA callback settings:

```text
Allowed Callback URLs: http://127.0.0.1:8787
Allowed Logout URLs: http://127.0.0.1:8787
Allowed Web Origins: http://127.0.0.1:8787
```

Okta:

```bash
OKTA_ISSUER=https://your-okta-domain.okta.com
OKTA_CLIENT_ID=...
OKTA_CLIENT_SECRET=...
OKTA_SCOPE=openid profile email
```

Use the Okta org issuer for general SSO. Use `/oauth2/default` only after configuring an Okta authorization-server access policy for this client.

Additional customer IdPs can be configured without code changes:

```bash
OIDC_PROVIDERS_JSON='[{"provider":"customer-a","issuer":"https://idp.example.com","clientId":"...","clientSecret":"...","scope":"openid profile email"}]'
```

## Core Endpoints

```text
GET  /.well-known/agent-authorization.json
GET  /.well-known/mission-authority-jwks.json
GET  /api/oauth/providers
GET  /api/oauth/login?provider=auth0|okta|customer-a
GET  /api/oauth/callback
POST /api/agents/passport
POST /api/missions/propose
POST /api/missions/approve
POST /api/mission/verify-checkpoint
POST /api/mission/enforce-checkpoint
POST /api/mission/export-bundle
```

`verify-checkpoint` is stateless and safe for external apps that need to decide whether an action is allowed. `enforce-checkpoint` mutates replay, ordering, budget, and enforcement-log state; in production it requires `MISSION_APPROVAL_BEARER_TOKEN`.

## SDK Usage

```js
import { ZkMissionAuthClient, verifyMissionBundle } from "agent-mission-bound-auth/sdk";

const auth = new ZkMissionAuthClient({ baseUrl: "http://127.0.0.1:8787" });
const discovery = await auth.discover();
const jwks = await auth.jwks();

const { agentPassport } = await auth.createAgentPassport({ agentId: "agent-1" });
const { mission } = await auth.proposeMission({
  agentId: agentPassport.agentId,
  task: "Send the approved report",
  operation: "email-send",
  datasetId: "customer-report",
  allowedTools: ["email.send"],
  allowedScopes: ["dataset:customer-report"],
  allowedRails: ["base"]
});
const { approval } = await auth.approveMission({ missionId: mission.missionId });

await auth.verifyCheckpoint({
  checkpoint: "before_external_side_effect",
  approval,
  context: {
    agentId: mission.agentId,
    datasetId: mission.datasetId,
    operation: mission.operation,
    action: "email.send",
    missionExecutionId: "exec-123",
    idempotencyKey: "email-123"
  }
});

const { bundle } = await auth.exportBundle({ agentPassport, mission, approval });
verifyMissionBundle(bundle, jwks);
```

## Checks

```bash
npm test
npm run smoke:protocol
npm run test:conformance
npm run test:browser-helper-conformance
npm run test:protocol-bindings
npm run test:conformance:remote
npm run test:oauth-sandbox
npm run oauth:sandbox-doctor
npm run test:production-hardening
```

## Deploy As A Sidecar

Set a public URL and provider secrets in the host environment:

```bash
PUBLIC_BASE_URL=https://auth-sidecar.example.com
MISSION_AUTH_PROFILE=production
DEMO_MODE=false
ZK_OAUTH_ISSUER_SECRET=...
MISSION_AUTHORITY_PRIVATE_JWK='{"kty":"EC","crv":"P-256",...}'
MISSION_APPROVAL_BEARER_TOKEN=...
MISSION_STATE_PATH=/var/lib/agent-mission-bound-auth/mission-state.json
REVOCATION_STATE_PATH=/var/lib/agent-mission-bound-auth/revocation-state.json
X402_TRUST_FACILITATOR_RECEIPTS=true
X402_FACILITATOR_ISSUER=https://facilitator.example
X402_FACILITATOR_JWKS_JSON='{"keys":[...]}'
```

Production `/api/oauth/zk-commit` verifies JWTs only against configured provider trust roots. Request-supplied issuer, audience, or JWKS URLs are ignored in production.

Container build:

```bash
docker build -t agent-mission-bound-auth .
docker run -p 8787:8787 --env-file .env.production agent-mission-bound-auth
```

For each customer IdP, add this callback URL:

```text
https://auth-sidecar.example.com/api/oauth/callback
```

No production Zeko operator is required for the local tutorial flow. Production deployments anchor mission approvals and receipt roots on Zeko with the scripts in `scripts/`.

## Live Zeko Testnet App

- zkApp: `B62qpBXMbrKVJwcS9wQN7SpFb6jkrXn2xrntCoM6D461qL2sYZarPHi`
- beneficiary: `B62qjxFhBZ2W1jzMyAppBkD22gGN66gTRYpX9AyaC4Kwga1kbC8zLBN`
- approval root: `18254630832314440409014986041827431424117053312046611743246600167702035963192`
- receipt root: `2503101496281787741527009452532014343190670744041313963524602789905044535138`

## Docs

- [Protocol spec](./docs/spec.md)
- [Generalized ZK architecture](./docs/generalized-zk-architecture.md)
- [Threat model](./docs/threat-model.md)
- [Portable receipt format](./docs/receipt-format.md)
- [Boundary event vocabulary](./docs/boundary-events.md)
- [Browser agent profile](./docs/browser-agent-profile.md)
- [Helper agent starter contract](./docs/helper-agent-starter.md)
- [Registry and nullifiers](./docs/registry-nullifiers.md)
- [Public verifier CLI](./docs/verifier-cli.md)
- [Integration guide](./docs/integration-guide.md)
- [OAuth provider setup](./docs/oauth-sandbox.md)
- [Security notes](./docs/security.md)

## Codex Skill

The repeatable build and review playbook is packaged as a local Codex skill:
[skills/agent-mission-bound-auth/SKILL.md](./skills/agent-mission-bound-auth/SKILL.md)

## License

Agent Mission-Bound Auth is part of the Zeko Agent Bundle. Protected
product/protocol-layer code is licensed under BUSL-1.1 with the Zeko Additional
Use Grant. Adoption-layer materials may be Apache-2.0 or MIT where expressly
marked.

The current Change Date is 2030-07-17, and the Change License is Apache
License, Version 2.0. Non-production/testnet use is free under the Additional
Use Grant. Production Agent Bundle deployments require the self-serve
commercial deployment license unless an Additional Free Use applies.

Standard self-serve pricing is published in [PRICING.md](./PRICING.md):

- Protocol Layer Production Deployments: $1,000/year per production rollup for
  1-10 production rollups; 11+ production rollups use custom pricing.
- Agent Bundle Production Deployments: $1,000/year per deploying legal entity
  per Deployment Network.

The self-serve commercial deployment license covers license rights only.
Managed deployment, enterprise support, compliance review, SLAs, custom
integrations, and dedicated infrastructure are separate commercial services.

See [LICENSING.md](./LICENSING.md), [LICENSE](./LICENSE),
[LICENSES/ZEKO-ADDITIONAL-USE-GRANT.md](./LICENSES/ZEKO-ADDITIONAL-USE-GRANT.md),
[COMMERCIAL-TERMS.md](./COMMERCIAL-TERMS.md), and [PRICING.md](./PRICING.md).
