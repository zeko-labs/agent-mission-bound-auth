import assert from "node:assert/strict";
import {
  ZEKO_NATIVE_ASSET,
  ZEKO_SEPOLIA_GRAPHQL,
  o1jsZekoSepoliaNetwork,
  zekoSepoliaConfig
} from "../packages/protocol/zeko-network.js";
import { RAILS } from "../packages/protocol/rails.js";

const config = zekoSepoliaConfig({});
assert.equal(config.graphql, ZEKO_SEPOLIA_GRAPHQL);
assert.equal(config.archive, ZEKO_SEPOLIA_GRAPHQL);
assert.equal(config.networkId, "zeko:sepolia");
assert.equal(config.protocolNetworkId, "zeko:sepolia");
assert.equal(config.graphqlNetworkId, "zeko:testnet");
assert.equal(config.signingNetworkId, "testnet");
assert.deepEqual(config.nativeAsset, ZEKO_NATIVE_ASSET);
assert.equal(config.transactionFee, "200000");
const previousGraphql = process.env.ZEKO_GRAPHQL;
const previousArchive = process.env.ZEKO_ARCHIVE;
process.env.ZEKO_GRAPHQL = ZEKO_SEPOLIA_GRAPHQL;
process.env.ZEKO_ARCHIVE = ZEKO_SEPOLIA_GRAPHQL;
const zekoRail = RAILS.zeko;
if (previousGraphql === undefined) delete process.env.ZEKO_GRAPHQL;
else process.env.ZEKO_GRAPHQL = previousGraphql;
if (previousArchive === undefined) delete process.env.ZEKO_ARCHIVE;
else process.env.ZEKO_ARCHIVE = previousArchive;
assert.equal(zekoRail.network, "zeko:sepolia");
assert.equal(
  zekoRail.extensions.zeko.protocolNetworkId,
  "zeko:sepolia"
);
assert.equal(
  zekoRail.extensions.zeko.graphqlNetworkId,
  "zeko:testnet"
);
assert.equal(zekoRail.extensions.zeko.signingNetworkId, "testnet");

const o1js = o1jsZekoSepoliaNetwork({
  ZEKO_GRAPHQL: "https://sepolia.zeko.io",
  ZEKO_ARCHIVE: "https://sepolia.zeko.io/graphql"
});
assert.deepEqual(o1js, {
  networkId: "testnet",
  mina: ZEKO_SEPOLIA_GRAPHQL,
  archive: ZEKO_SEPOLIA_GRAPHQL
});

for (const invalid of [
  { ZEKO_PROTOCOL_NETWORK_ID: "zeko:testnet" },
  { ZEKO_NETWORK_ID: "zeko:testnet" },
  { ZEKO_NETWORK_ID: "zeko" },
  { ZEKO_NATIVE_ASSET: "tMINA" },
  { ZEKO_NATIVE_DECIMALS: "18" },
  { ZEKO_NATIVE_TOKEN_ID: "wrong-token-id" },
  { ZEKO_GRAPHQL: "https://testnet.zeko.io/graphql" },
  { ZEKO_ARCHIVE: "https://archive.testnet.zeko.io/graphql" }
]) {
  assert.throws(
    () => zekoSepoliaConfig(invalid),
    /Zeko Ethereum Sepolia profile|Sepolia-only/
  );
}

console.log(JSON.stringify({
  ok: true,
  checks: [
    "sepolia-endpoint-default",
    "protocol-network-id",
    "graphql-network-id",
    "x402-rail-network-metadata",
    "testnet-signing-domain",
    "seth-native-asset",
    "sepolia-static-fee",
    "mixed-network-config-rejection"
  ]
}, null, 2));
