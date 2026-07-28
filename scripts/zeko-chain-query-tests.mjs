import assert from "node:assert/strict";
import {
  fetchZekoTransactionStatus
} from "../packages/protocol/zeko-chain.js";

const registryAddress =
  "B62qokikatWpFvyqGG9NekejnFEumRyUjrbjChaQfrvDmKwTC3UXzzz";
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
  graphql: "https://testnet.zeko.io/graphql",
  registryAddress,
  transactionHash
});
assert.equal(included.included, true);
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
  graphql: "https://testnet.zeko.io/graphql",
  registryAddress,
  transactionHash
});
assert.equal(nonCanonical.included, false);

responseBody = { data: { events: [] } };
const missing = await fetchZekoTransactionStatus({
  graphql: "https://testnet.zeko.io/graphql",
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
    "noncanonical-rejection",
    "missing-transaction-rejection"
  ]
}, null, 2));
