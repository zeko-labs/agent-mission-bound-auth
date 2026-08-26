import { zekoSepoliaConfig } from "../packages/protocol/zeko-network.js";

const config = zekoSepoliaConfig(process.env);
let response;
try {
  response = await fetch(config.graphql, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      query: `query ZekoSepoliaIdentity {
        networkID
        syncStatus
        sequencerPk
        signatureKind
        genesisConstants { accountCreationFee }
        daemonStatus { chainId }
      }`
    })
  });
} catch (error) {
  console.error(JSON.stringify({
    ok: false,
    graphql: config.graphql,
    error: error instanceof Error ? error.message : String(error)
  }, null, 2));
  process.exit(1);
}

const responseText = await response.text();
let body;
try {
  body = JSON.parse(responseText);
} catch {
  body = null;
}
if (!response.ok || !body || body.errors?.length) {
  console.error(JSON.stringify({
    ok: false,
    graphql: config.graphql,
    status: response.status,
    errors: body?.errors ?? null,
    response: body ? undefined : responseText.slice(0, 300)
  }, null, 2));
  process.exit(1);
}

const observed = body.data ?? {};
const ok =
  observed.networkID === config.networkId &&
  String(observed.signatureKind).toLowerCase() ===
    config.signingNetworkId &&
  observed.syncStatus === "SYNCED" &&
  Boolean(observed.sequencerPk) &&
  /^[0-9]+$/.test(observed.genesisConstants?.accountCreationFee ?? "");

console.log(JSON.stringify({
  ok,
  network: {
    name: config.networkName,
    graphql: config.graphql,
    networkId: observed.networkID,
    signingNetworkId: config.signingNetworkId,
    signatureKind: observed.signatureKind,
    chainId: observed.daemonStatus?.chainId ?? null,
    syncStatus: observed.syncStatus,
    sequencerPk: observed.sequencerPk,
    accountCreationFee: observed.genesisConstants?.accountCreationFee,
    nativeAsset: config.nativeAsset,
    transactionFee: config.transactionFee
  }
}, null, 2));

process.exit(ok ? 0 : 1);
