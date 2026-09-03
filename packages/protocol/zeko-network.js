export const ZEKO_GRAPHQL_NETWORK_ID = "zeko:testnet";
export const ZEKO_SIGNING_NETWORK_ID = "testnet";
export const ZEKO_NETWORK_NAME = "Zeko Ethereum Sepolia";
export const ZEKO_SEPOLIA_GRAPHQL = "https://sepolia.zeko.io/graphql";
export const ZEKO_MISSION_REGISTRY_ADDRESS =
  "B62qikuceF52NVPb8VAVSaRoCRMusFz38pLLENjvLaUuLiDnULAVohe";
export const ZEKO_NATIVE_ASSET = Object.freeze({
  symbol: "sETH",
  decimals: 9,
  standard: "native",
  tokenId: "wSHV2S4qX9jFsLjQo8r1BsMLH2ZRKsZx6EJd1sbozGPieEC4Jf"
});
export const ZEKO_DEFAULT_TX_FEE = "200000";

function fixedSetting(env, name, expected) {
  const value = env[name];
  if (value !== undefined && String(value) !== String(expected)) {
    throw new Error(
      `${name} must be ${expected} for the Zeko Ethereum Sepolia profile.`
    );
  }
  return expected;
}

export function normalizeZekoGraphqlUrl(value = ZEKO_SEPOLIA_GRAPHQL) {
  return value.endsWith("/graphql")
    ? value
    : `${value.replace(/\/$/, "")}/graphql`;
}

export function zekoSepoliaConfig(env = process.env) {
  const graphql = normalizeZekoGraphqlUrl(
    env.ZEKO_GRAPHQL ?? ZEKO_SEPOLIA_GRAPHQL
  );
  if (graphql !== ZEKO_SEPOLIA_GRAPHQL) {
    throw new Error(
      `ZEKO_GRAPHQL must be ${ZEKO_SEPOLIA_GRAPHQL}; ` +
      "the active MBA profile is Sepolia-only."
    );
  }
  const archive = normalizeZekoGraphqlUrl(env.ZEKO_ARCHIVE ?? graphql);
  if (archive !== ZEKO_SEPOLIA_GRAPHQL) {
    throw new Error(
      `ZEKO_ARCHIVE must be ${ZEKO_SEPOLIA_GRAPHQL}; ` +
      "the active MBA profile is Sepolia-only."
    );
  }
  return {
    networkId: ZEKO_GRAPHQL_NETWORK_ID,
    signingNetworkId: fixedSetting(
      env,
      "ZEKO_NETWORK_ID",
      ZEKO_SIGNING_NETWORK_ID
    ),
    networkName: fixedSetting(
      env,
      "ZEKO_NETWORK_NAME",
      ZEKO_NETWORK_NAME
    ),
    graphql,
    archive,
    nativeAsset: {
      symbol: fixedSetting(
        env,
        "ZEKO_NATIVE_ASSET",
        ZEKO_NATIVE_ASSET.symbol
      ),
      decimals: Number(fixedSetting(
        env,
        "ZEKO_NATIVE_DECIMALS",
        ZEKO_NATIVE_ASSET.decimals
      )),
      standard: ZEKO_NATIVE_ASSET.standard,
      tokenId: fixedSetting(
        env,
        "ZEKO_NATIVE_TOKEN_ID",
        ZEKO_NATIVE_ASSET.tokenId
      )
    },
    transactionFee: env.TX_FEE ?? ZEKO_DEFAULT_TX_FEE,
    explorer: env.ZEKO_EXPLORER_URL || null
  };
}

export function o1jsZekoSepoliaNetwork(env = process.env) {
  const config = zekoSepoliaConfig(env);
  return {
    networkId: config.signingNetworkId,
    mina: config.graphql,
    archive: config.archive
  };
}
