import "reflect-metadata";

import fs from "node:fs";
import path from "node:path";
import {
  AccountUpdate,
  Mina,
  PrivateKey,
  PublicKey,
  UInt64,
  fetchAccount
} from "o1js";
import {
  MissionRegistry,
  MissionRegistryConfig
} from "../dist-zkapp/MissionRegistry.js";
import {
  requireEnv,
  zekoConfig,
  zekoNetwork
} from "./lib/registry-state.mjs";

const network = zekoNetwork();
const networkConfig = zekoConfig();
const fee = UInt64.from(networkConfig.transactionFee);
const deployerKey = PrivateKey.fromBase58(
  requireEnv("DEPLOYER_PRIVATE_KEY")
);
const zkappKey = PrivateKey.fromBase58(requireEnv("ZKAPP_PRIVATE_KEY"));
const authorityKey = PublicKey.fromBase58(
  process.env.MISSION_AUTHORITY_ZEKO_PUBLIC_KEY ??
  PrivateKey.fromBase58(
    requireEnv("MISSION_AUTHORITY_ZEKO_PRIVATE_KEY")
  ).toPublicKey().toBase58()
);
const protocolFeeRecipient = PublicKey.fromBase58(
  requireEnv(
    "MISSION_PROTOCOL_FEE_RECIPIENT",
    "PRIVATE_COMPUTE_BENEFICIARY_PUBLIC_KEY"
  )
);
const deployer = deployerKey.toPublicKey();
const zkappAddress = zkappKey.toPublicKey();

if (
  process.env.DEPLOYER_PUBLIC_KEY &&
  deployer.toBase58() !== process.env.DEPLOYER_PUBLIC_KEY
) {
  throw new Error("DEPLOYER_PRIVATE_KEY does not match DEPLOYER_PUBLIC_KEY.");
}

Mina.setActiveInstance(Mina.Network(network));
await MissionRegistry.compile();
const deployerAccount = await fetchAccount({ publicKey: deployer });
if (deployerAccount.error) {
  throw new Error(`Deployer account not found: ${deployer.toBase58()}`);
}
const existing = await fetchAccount({ publicKey: zkappAddress });
if (!existing.error) {
  throw new Error(
    `Account ${zkappAddress.toBase58()} already exists; use a fresh ZKAPP_PRIVATE_KEY for MissionRegistry.`
  );
}

const registry = new MissionRegistry(zkappAddress);
const deployTx = await Mina.transaction(
  { sender: deployer, fee },
  async () => {
    AccountUpdate.fundNewAccount(deployer);
    await registry.deploy();
  }
);
await deployTx.prove();
const deployResult = await deployTx.sign([deployerKey, zkappKey]).send();
await deployResult.wait();
await fetchAccount({ publicKey: zkappAddress });

const configureTx = await Mina.transaction(
  { sender: deployer, fee },
  async () => {
    await registry.configure(
      new MissionRegistryConfig({
        authorityKey,
        protocolFeeRecipient
      })
    );
  }
);
await configureTx.prove();
const configureResult = await configureTx
  .sign([deployerKey, zkappKey])
  .send();
await configureResult.wait();

await fetchAccount({ publicKey: zkappAddress });
const deployment = {
  version: "mba-mission-registry-deployment-v1",
  ok: true,
  contract: "MissionRegistry",
  zkappAddress: zkappAddress.toBase58(),
  authorityKey: authorityKey.toBase58(),
  protocolFeeRecipient: protocolFeeRecipient.toBase58(),
  deployTransactionHash: deployResult.hash,
  configureTransactionHash: configureResult.hash,
  registryRoot: registry.registryRoot.get().toString(),
  sequence: registry.sequence.get().toString(),
  deployedAt: new Date().toISOString(),
  network: {
    id: networkConfig.networkId,
    name: networkConfig.networkName,
    signingNetworkId: networkConfig.signingNetworkId,
    graphql: networkConfig.graphql,
    nativeAsset: networkConfig.nativeAsset
  }
};
const outputPath =
  process.env.MISSION_REGISTRY_DEPLOYMENT_PATH ??
  path.join(
    process.cwd(),
    "data",
    "deployment.mission-registry.zeko-sepolia.json"
  );
fs.mkdirSync(path.dirname(outputPath), { recursive: true });
const temporary = `${outputPath}.${process.pid}.${Date.now()}.tmp`;
fs.writeFileSync(temporary, `${JSON.stringify(deployment, null, 2)}\n`);
fs.renameSync(temporary, outputPath);

console.log(JSON.stringify({
  ...deployment,
  deploymentPath: path.relative(process.cwd(), outputPath)
}, null, 2));
