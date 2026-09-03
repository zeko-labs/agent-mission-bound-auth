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
import { compileMissionRegistry } from "./lib/compile-mission-registry.mjs";
import { waitForAccountState } from "./lib/zeko-confirmation.mjs";

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
const outputPath =
  process.env.MISSION_REGISTRY_DEPLOYMENT_PATH ??
  path.join(
    process.cwd(),
    "data",
    "deployment.mission-registry.zeko-sepolia.json"
  );
let previousDeployment = null;
if (fs.existsSync(outputPath)) {
  const parsed = JSON.parse(fs.readFileSync(outputPath, "utf8"));
  if (parsed.zkappAddress === zkappAddress.toBase58()) {
    previousDeployment = parsed;
  }
}

if (
  process.env.DEPLOYER_PUBLIC_KEY &&
  deployer.toBase58() !== process.env.DEPLOYER_PUBLIC_KEY
) {
  throw new Error("DEPLOYER_PRIVATE_KEY does not match DEPLOYER_PUBLIC_KEY.");
}

Mina.setActiveInstance(Mina.Network(network));
const { verificationKey } = await compileMissionRegistry();
const deployerAccount = await fetchAccount({ publicKey: deployer });
if (deployerAccount.error) {
  throw new Error(`Deployer account not found: ${deployer.toBase58()}`);
}
const registry = new MissionRegistry(zkappAddress);
let existing = await fetchAccount({ publicKey: zkappAddress });
let deployTransactionHash =
  previousDeployment?.deployTransactionHash ?? null;
let deployStatus = "confirmed_existing";

if (existing.error) {
  const deployTx = await Mina.transaction(
    { sender: deployer, fee },
    async () => {
      AccountUpdate.fundNewAccount(deployer);
      await registry.deploy();
    }
  );
  await deployTx.prove();
  const deployResult = await deployTx.sign([deployerKey, zkappKey]).send();
  deployTransactionHash = deployResult.hash;
  deployStatus = "submitted";
  await waitForAccountState(zkappAddress, () => true, {
    description: "MissionRegistry deployment"
  });
  deployStatus = "confirmed";
  existing = await fetchAccount({ publicKey: zkappAddress });
}

const onChainVerificationKeyHash =
  existing.account?.zkapp?.verificationKey?.hash?.toString();
if (onChainVerificationKeyHash !== verificationKey.hash.toString()) {
  throw new Error(
    `MissionRegistry verification key mismatch at ${zkappAddress.toBase58()}.`
  );
}

const currentAuthority = registry.authorityKey.get();
const currentFeeRecipient = registry.protocolFeeRecipient.get();
const isUnconfigured = currentAuthority.isEmpty().toBoolean() &&
  currentFeeRecipient.isEmpty().toBoolean();
const isExpectedConfiguration = currentAuthority
  .equals(authorityKey)
  .toBoolean() && currentFeeRecipient
  .equals(protocolFeeRecipient)
  .toBoolean();

if (!isUnconfigured && !isExpectedConfiguration) {
  throw new Error(
    `MissionRegistry ${zkappAddress.toBase58()} is configured with unexpected keys.`
  );
}

let configureTransactionHash =
  previousDeployment?.configureTransactionHash ?? null;
let configureStatus = "confirmed_existing";
if (isUnconfigured) {
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
  configureTransactionHash = configureResult.hash;
  configureStatus = "submitted";
  await waitForAccountState(
    zkappAddress,
    () => {
      const observed = new MissionRegistry(zkappAddress);
      return observed.authorityKey.get().equals(authorityKey).toBoolean() &&
        observed.protocolFeeRecipient
          .get()
          .equals(protocolFeeRecipient)
          .toBoolean();
    },
    { description: "MissionRegistry configuration" }
  );
  configureStatus = "confirmed";
}

await fetchAccount({ publicKey: zkappAddress });
const deployment = {
  version: "mba-mission-registry-deployment-v1",
  ok: true,
  contract: "MissionRegistry",
  zkappAddress: zkappAddress.toBase58(),
  authorityKey: authorityKey.toBase58(),
  protocolFeeRecipient: protocolFeeRecipient.toBase58(),
  deployer: deployer.toBase58(),
  verificationKeyHash: verificationKey.hash.toString(),
  transactionFeeNativeUnits: fee.toString(),
  deployTransactionHash,
  deployStatus,
  configureTransactionHash,
  configureStatus,
  registryRoot: registry.registryRoot.get().toString(),
  sequence: registry.sequence.get().toString(),
  deployedAt:
    previousDeployment?.deployedAt ?? new Date().toISOString(),
  network: {
    id: networkConfig.networkId,
    name: networkConfig.networkName,
    signingNetworkId: networkConfig.signingNetworkId,
    graphql: networkConfig.graphql,
    nativeAsset: networkConfig.nativeAsset
  },
  ...(previousDeployment?.deployTransactionHashNote
    ? {
        deployTransactionHashNote:
          previousDeployment.deployTransactionHashNote
      }
    : {}),
  ...(previousDeployment?.acceptance
    ? { acceptance: previousDeployment.acceptance }
    : {})
};
fs.mkdirSync(path.dirname(outputPath), { recursive: true });
const temporary = `${outputPath}.${process.pid}.${Date.now()}.tmp`;
fs.writeFileSync(temporary, `${JSON.stringify(deployment, null, 2)}\n`);
fs.renameSync(temporary, outputPath);

console.log(JSON.stringify({
  ...deployment,
  deploymentPath: path.relative(process.cwd(), outputPath)
}, null, 2));
