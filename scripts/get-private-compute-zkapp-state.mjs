import "reflect-metadata";

import { Mina, PublicKey, fetchAccount } from "o1js";
import { MissionRegistry } from "../dist-zkapp/MissionRegistry.js";
import {
  requireEnv,
  zekoNetwork
} from "./lib/registry-state.mjs";

const network = zekoNetwork();
const zkappAddress = PublicKey.fromBase58(
  requireEnv(
    "MISSION_REGISTRY_PUBLIC_KEY",
    "PRIVATE_COMPUTE_ZKAPP_PUBLIC_KEY"
  )
);
Mina.setActiveInstance(Mina.Network(network));
const fetched = await fetchAccount({ publicKey: zkappAddress });
if (fetched.error) {
  throw new Error(`MissionRegistry account not found: ${zkappAddress.toBase58()}`);
}
const registry = new MissionRegistry(zkappAddress);
console.log(JSON.stringify({
  ok: true,
  contract: "MissionRegistry",
  zkappAddress: zkappAddress.toBase58(),
  authorityKey: registry.authorityKey.get().toBase58(),
  protocolFeeRecipient: registry.protocolFeeRecipient.get().toBase58(),
  registryRoot: registry.registryRoot.get().toString(),
  sequence: registry.sequence.get().toString(),
  network
}, null, 2));
