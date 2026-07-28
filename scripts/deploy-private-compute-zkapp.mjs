import "reflect-metadata";

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
  zekoNetwork
} from "./lib/registry-state.mjs";

const network = zekoNetwork();
const fee = UInt64.from(process.env.TX_FEE ?? "2000000000");
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

Mina.setActiveInstance(Mina.Network(network));
await MissionRegistry.compile();
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

console.log(JSON.stringify({
  ok: true,
  contract: "MissionRegistry",
  zkappAddress: zkappAddress.toBase58(),
  authorityKey: authorityKey.toBase58(),
  protocolFeeRecipient: protocolFeeRecipient.toBase58(),
  deployTransactionHash: deployResult.hash,
  configureTransactionHash: configureResult.hash,
  network
}, null, 2));
