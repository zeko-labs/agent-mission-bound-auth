import assert from "node:assert/strict";
import {
  fetchZekoTransactionStatus,
  isZekoTransactionConfirmedForAnchor
} from "../packages/protocol/zeko-chain.js";
import { ZEKO_MISSION_REGISTRY_ADDRESS } from
  "../packages/protocol/zeko-network.js";

const registryAddress = ZEKO_MISSION_REGISTRY_ADDRESS;
const transactionHash = "5Jtransaction";
let responseBody = {
  data: {
    events: [{
      blockInfo: {
        height: 42,
        chainStatus: "canonical"
      },
      eventData: [{
        transactionInfo: {
          status: "applied",
          hash: transactionHash,
          sequenceNumber: 7
        }
      }]
    }]
  }
};

globalThis.fetch = async (_url, init) => {
  const request = JSON.parse(init.body);
  assert.match(request.query, /events\(input: \$input\)/);
  assert.equal(request.variables.input.address, registryAddress);
  return Response.json(responseBody);
};

const included = await fetchZekoTransactionStatus({
  graphql: "https://sepolia.zeko.io/graphql",
  registryAddress,
  transactionHash
});
assert.equal(included.included, true);
assert.equal(included.applied, true);
assert.equal(included.canonical, true);
assert.equal(included.blockHeight, 42);
assert.equal(included.sequenceNumber, 7);

responseBody = {
  data: {
    events: [{
      blockInfo: {
        height: 43,
        chainStatus: "pending"
      },
      eventData: [{
        transactionInfo: {
          status: "applied",
          hash: transactionHash,
          sequenceNumber: 8
        }
      }]
    }]
  }
};
const nonCanonical = await fetchZekoTransactionStatus({
  graphql: "https://sepolia.zeko.io/graphql",
  registryAddress,
  transactionHash
});
assert.equal(nonCanonical.included, false);

responseBody = {
  data: {
    events: [{
      blockInfo: {
        height: 0,
        chainStatus: ""
      },
      eventData: [{
        transactionInfo: {
          status: '["Applied"]',
          hash: transactionHash,
          sequenceNumber: 0
        }
      }]
    }]
  }
};
const sequencerApplied = await fetchZekoTransactionStatus({
  graphql: "https://sepolia.zeko.io/graphql",
  registryAddress,
  transactionHash
});
assert.equal(sequencerApplied.included, false);
assert.equal(sequencerApplied.applied, true);
assert.equal(sequencerApplied.canonical, false);
assert.equal(sequencerApplied.status, "applied");
const currentState = { registryRoot: "root-1", sequence: "1" };
const currentAnchor = { registryRoot: "root-1", sequence: "1" };
assert.equal(
  isZekoTransactionConfirmedForAnchor(
    sequencerApplied,
    currentState,
    currentAnchor
  ),
  true
);
assert.equal(
  isZekoTransactionConfirmedForAnchor(
    sequencerApplied,
    currentState,
    { ...currentAnchor, registryRoot: "wrong-root" }
  ),
  false
);
assert.equal(
  isZekoTransactionConfirmedForAnchor(
    sequencerApplied,
    currentState,
    { ...currentAnchor, sequence: "0" }
  ),
  false
);
assert.equal(
  isZekoTransactionConfirmedForAnchor(
    { ...sequencerApplied, chainStatus: "pending" },
    currentState,
    currentAnchor
  ),
  false
);

responseBody = { data: { events: [] } };
const missing = await fetchZekoTransactionStatus({
  graphql: "https://sepolia.zeko.io/graphql",
  registryAddress,
  transactionHash
});
assert.equal(missing.included, false);
assert.equal(missing.status, "not_found");

console.log(JSON.stringify({
  ok: true,
  checks: [
    "zeko-events-query",
    "applied-canonical-inclusion",
    "redeployed-gateway-applied-status-normalization",
    "gateway-fallback-requires-exact-current-state",
    "noncanonical-rejection",
    "missing-transaction-rejection"
  ]
}, null, 2));
