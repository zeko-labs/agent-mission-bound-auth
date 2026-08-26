import fs from "node:fs";
import { loadLocalEnv } from "../packages/protocol/env-local.js";
import {
  isSettlementEnabled,
  isZekoSettlementProfile,
  missionAuthProfile,
  missionSettlementProfile
} from "../packages/protocol/runtime.js";
import { zekoSepoliaConfig } from "../packages/protocol/zeko-network.js";

loadLocalEnv();

function required(name) {
  return {
    name,
    present: Boolean(process.env[name]),
    value: process.env[name] ? "set" : "missing"
  };
}

async function checkJwks() {
  const url = process.env.OIDC_JWKS_URL;
  if (!url) {
    return { ok: false, skipped: true, reason: "OIDC_JWKS_URL missing" };
  }

  try {
    const res = await fetch(url);
    const body = await res.json();
    return {
      ok: res.ok && Array.isArray(body.keys),
      status: res.status,
      keyCount: Array.isArray(body.keys) ? body.keys.length : 0
    };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error.message : String(error) };
  }
}

async function checkZeko() {
  if (!isZekoSettlementProfile()) {
    return {
      ok: true,
      skipped: true,
      reason: "Zeko settlement profile is not active."
    };
  }
  const config = zekoSepoliaConfig(process.env);
  const graphql = config.graphql;

  try {
    const res = await fetch(graphql, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        query: `query ZekoSepoliaIdentity {
          networkID
          syncStatus
          sequencerPk
          signatureKind
          genesisConstants { accountCreationFee }
        }`
      })
    });
    const body = await res.json();
    return {
      ok:
        res.ok &&
        body.data?.networkID === config.networkId &&
        String(body.data?.signatureKind).toLowerCase() ===
          config.signingNetworkId &&
        body.data?.syncStatus === "SYNCED" &&
        Boolean(body.data?.sequencerPk),
      graphql,
      networkId: body.data?.networkID ?? null,
      signingNetworkId: config.signingNetworkId,
      signatureKind: body.data?.signatureKind ?? null,
      syncStatus: body.data?.syncStatus ?? null,
      sequencerPk: body.data?.sequencerPk ?? null,
      accountCreationFee:
        body.data?.genesisConstants?.accountCreationFee ?? null,
      nativeAsset: config.nativeAsset,
      errors: body.errors ?? null
    };
  } catch (error) {
    return { ok: false, graphql, error: error instanceof Error ? error.message : String(error) };
  }
}

const oidc = [
  required("MISSION_AUTH_PROFILE"),
  required("DEMO_MODE"),
  required("PUBLIC_BASE_URL"),
  required("OIDC_ISSUER"),
  required("OIDC_AUDIENCE"),
  required("OIDC_JWKS_URL")
];
const authority = [
  required("ZK_OAUTH_ISSUER_SECRET"),
  required("MISSION_AUTHORITY_PRIVATE_JWK"),
  required("MISSION_APPROVAL_BEARER_TOKEN"),
  required("MISSION_STATE_PATH"),
  required("REVOCATION_STATE_PATH"),
  ...(isZekoSettlementProfile()
    ? [required("DOMAIN_VERIFIER_PALLAS_PUBLIC_KEYS_JSON")]
    : [])
];
const settlement = isSettlementEnabled()
  ? [required("X402_FACILITATOR_URL")]
  : [];
const zekoDeploy = isZekoSettlementProfile()
  ? [
      required("DEPLOYER_PRIVATE_KEY"),
      required("ZKAPP_PRIVATE_KEY"),
      required("MISSION_AUTHORITY_ZEKO_PRIVATE_KEY"),
      required("MISSION_PROTOCOL_FEE_RECIPIENT"),
      required("MISSION_REGISTRY_PUBLIC_KEY"),
      required("MISSION_REGISTRY_STATE_PATH"),
      required("ZEKO_GRAPHQL")
    ]
  : [];
const zkappBuild = {
  ok:
    !isZekoSettlementProfile() ||
    (
      fs.existsSync("dist-zkapp/MissionComplianceProgram.js") &&
      fs.existsSync("dist-zkapp/MissionRegistry.js")
    ),
  skipped: !isZekoSettlementProfile(),
  paths: [
    "dist-zkapp/MissionComplianceProgram.js",
    "dist-zkapp/MissionRegistry.js"
  ]
};
const jwks = await checkJwks();
const zeko = await checkZeko();

const ok =
  oidc.every((item) => item.present) &&
  authority.every((item) => item.present) &&
  settlement.every((item) => item.ok ?? item.present) &&
  jwks.ok &&
  zekoDeploy.every((item) => item.present) &&
  zeko.ok &&
  zkappBuild.ok;

console.log(JSON.stringify({
  ok,
  profiles: {
    auth: missionAuthProfile(),
    settlement: missionSettlementProfile()
  },
  oidc,
  authority,
  settlement,
  jwks,
  zekoDeploy,
  zeko,
  zkappBuild,
  nextMissing: [
    ...oidc.filter((item) => !item.present).map((item) => item.name),
    ...authority.filter((item) => !item.present).map((item) => item.name),
    ...settlement.filter((item) => !(item.ok ?? item.present)).map((item) => item.name),
    ...(jwks.ok ? [] : ["valid OIDC JWKS"]),
    ...zekoDeploy.filter((item) => !item.present).map((item) => item.name),
    ...(zeko.ok ? [] : ["reachable Zeko GraphQL"]),
    ...(zkappBuild.ok ? [] : ["npm run zkapp:build"])
  ]
}, null, 2));

process.exit(ok ? 0 : 1);
