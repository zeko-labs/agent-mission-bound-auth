import {
  isProductionProfile,
  isSettlementEnabled
} from "./runtime.js";

const env = process.env;

function decimalToUnits(value, decimals) {
  const normalized = String(value);
  if (!/^(0|[1-9][0-9]*)(\.[0-9]+)?$/.test(normalized)) {
    throw new Error(`Invalid non-negative decimal amount: ${value}`);
  }
  const [whole, fraction = ""] = normalized.split(".");
  if (fraction.length > decimals) {
    throw new Error(`Amount ${value} exceeds ${decimals} decimals.`);
  }
  return (
    BigInt(whole) * (10n ** BigInt(decimals)) +
    BigInt((fraction + "0".repeat(decimals)).slice(0, decimals) || "0")
  ).toString();
}

function graphqlUrl(value, fallback) {
  const url = value ?? fallback;
  return url.endsWith("/graphql") ? url : `${url.replace(/\/$/, "")}/graphql`;
}

function evmRail(input) {
  const displayAmount = input.amount;
  return {
    id: input.id,
    settlementRail: "evm",
    network: input.network,
    chainName: input.chainName,
    asset: input.asset,
    assetId: input.asset.address,
    amount: decimalToUnits(displayAmount, input.asset.decimals),
    displayAmount,
    payTo: input.payTo,
    settlementModel: input.settlementModel,
    description: input.description,
    preview: input.preview ?? false,
    configured: Boolean(input.configured),
    extensions: {
      evm: {
        chainId: input.chainId,
        chainName: input.chainName,
        eip712Name: input.eip712Name,
        transferMethod: input.transferMethod ?? "EIP-3009",
        ...(input.rpcUrl ? { rpcUrl: input.rpcUrl } : {}),
        ...(input.explorer ? { explorer: input.explorer } : {}),
        ...(input.extrapolated ? { extrapolated: true } : {})
      }
    }
  };
}

function buildRails() {
  return {
  zeko: {
    id: "zeko",
    settlementRail: "zeko",
    network: "zeko:testnet",
    chainName: "Zeko Testnet",
    asset: { symbol: "tMINA", decimals: 9, standard: "native" },
    assetId: "MINA",
    amount: decimalToUnits(env.ZEKO_AMOUNT ?? "0.015", 9),
    displayAmount: env.ZEKO_AMOUNT ?? "0.015",
    payTo:
      env.MISSION_REGISTRY_PUBLIC_KEY ??
      env.ZEKO_PAY_TO ??
      "B62qokikatWpFvyqGG9NekejnFEumRyUjrbjChaQfrvDmKwTC3UXzzz",
    settlementModel: "x402-exact-settlement-zkapp-v1",
    description: "Zeko-native settlement for ZK-authorized private compute.",
    preview: false,
    configured: Boolean(
      env.MISSION_REGISTRY_PUBLIC_KEY ?? env.ZEKO_PAY_TO
    ),
    extensions: {
      zeko: {
        primitive: "zeko-exact-settlement-zkapp-v1",
        contractAddress:
          env.MISSION_REGISTRY_PUBLIC_KEY ??
          env.ZEKO_PAY_TO ??
          null,
        beneficiaryAddress:
          env.ZEKO_BENEFICIARY ??
          "B62qokikatWpFvyqGG9NekejnFEumRyUjrbjChaQfrvDmKwTC3UXzzz",
        graphql: graphqlUrl(env.ZEKO_GRAPHQL, "https://testnet.zeko.io/graphql"),
        archive: graphqlUrl(env.ZEKO_ARCHIVE, "https://archive.testnet.zeko.io/graphql"),
        explorer: "https://zekoscan.io/testnet",
        programmablePrivacy: {
          auth: "zk-oauth-v1",
          data: "private-compute-commitment-v1",
          disclosure: "aggregate-output-only"
        },
        kernelPath: ["privateCompute.authorize", "x402Settlement.settleExact"]
      }
    }
  },
  ethereum: evmRail({
    id: "ethereum",
    network: "eip155:1",
    chainId: 1,
    chainName: "Ethereum",
    asset: {
      symbol: "USDC",
      decimals: 6,
      standard: "erc20",
      address: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
    },
    amount: env.ETHEREUM_AMOUNT ?? "0.050000",
    payTo: env.ETHEREUM_PAY_TO ?? "0x2222222222222222222222222222222222222222",
    settlementModel: "x402-exact-eip3009-v1",
    description: "Ethereum mainnet USDC payment through x402 EIP-3009 authorization.",
    eip712Name: "USD Coin",
    configured: Boolean(env.ETHEREUM_PAY_TO)
  }),
  base: evmRail({
    id: "base",
    network: "eip155:8453",
    chainId: 8453,
    chainName: "Base",
    asset: {
      symbol: "USDC",
      decimals: 6,
      standard: "erc20",
      address: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
    },
    amount: env.BASE_AMOUNT ?? "0.050000",
    payTo: env.BASE_PAY_TO ?? "0x1111111111111111111111111111111111111111",
    settlementModel: "x402-exact-eip3009-v1",
    description: "Base USDC payment through x402 EIP-3009 authorization.",
    eip712Name: "USD Coin",
    configured: Boolean(env.BASE_PAY_TO)
  }),
  arc: evmRail({
    id: "arc",
    network: "eip155:5042002",
    chainId: 5042002,
    chainName: "Arc Testnet",
    asset: {
      symbol: "USDC",
      decimals: 6,
      standard: "erc20",
      address:
        env.ARC_ASSET ??
        "0x0000000000000000000000000000000000000001"
    },
    amount: env.ARC_AMOUNT ?? "0.050000",
    payTo: env.ARC_PAY_TO ?? "0x3333333333333333333333333333333333333333",
    settlementModel: "x402-exact-arc-usdc-v1",
    description: "Arc testnet USDC rail extrapolated from the EVM x402 facilitator path.",
    rpcUrl: "https://rpc.testnet.arc.network",
    explorer: "https://testnet.arcscan.app",
    extrapolated: true,
    preview: true,
    configured:
      env.ENABLE_ARC_RAIL === "true" &&
      Boolean(env.ARC_PAY_TO) &&
      Boolean(env.ARC_ASSET)
  }),
  tempo: evmRail({
    id: "tempo",
    network: "eip155:42431",
    chainId: 42431,
    chainName: "Tempo Moderato",
    asset: {
      symbol: "USD",
      decimals: 6,
      standard: "erc20",
      address:
        env.TEMPO_ASSET ??
        "0x0000000000000000000000000000000000000002"
    },
    amount: env.TEMPO_AMOUNT ?? "0.050000",
    payTo: env.TEMPO_PAY_TO ?? "0x4444444444444444444444444444444444444444",
    settlementModel: "x402-exact-tempo-usd-v1",
    description: "Tempo rail extrapolated from the EVM x402 facilitator path.",
    rpcUrl: "https://rpc.moderato.tempo.xyz",
    explorer: "https://explore.tempo.xyz",
    extrapolated: true,
    preview: true,
    configured:
      env.ENABLE_TEMPO_RAIL === "true" &&
      Boolean(env.TEMPO_PAY_TO) &&
      Boolean(env.TEMPO_ASSET)
  })
  };
}

export const RAILS = new Proxy({}, {
  get(_target, property) {
    return buildRails()[property];
  },
  ownKeys() {
    return Reflect.ownKeys(buildRails());
  },
  getOwnPropertyDescriptor() {
    return { enumerable: true, configurable: true };
  }
});

export function enabledRails() {
  const rails = [
    RAILS.zeko,
    RAILS.ethereum,
    RAILS.base,
    RAILS.arc,
    RAILS.tempo
  ];
  if (!isProductionProfile()) return rails;
  if (!isSettlementEnabled()) return [];
  return rails.filter((rail) => rail.configured);
}

export function findRail(idOrNetwork) {
  return enabledRails().find((rail) => rail.id === idOrNetwork || rail.network === idOrNetwork);
}
