import assert from "node:assert/strict";

process.env.MISSION_AUTH_PROFILE = "production";
process.env.DEMO_MODE = "false";
process.env.PUBLIC_BASE_URL = "https://mba.example";
process.env.BASE_URL = "https://mba.example";
process.env.ETHEREUM_PAY_TO = "0x2222222222222222222222222222222222222222";
process.env.X402_FACILITATOR_URL = "https://facilitator.example";

const {
  MBA_X402_EXTENSION,
  buildPaymentRequirement,
  buildPaymentResponse,
  paymentRequirementId,
  verifyAndSettlePayment
} = await import("../packages/protocol/x402.js");

const requirement = buildPaymentRequirement({
  jobId: "job_x402_v2",
  datasetId: "dataset_committed",
  operation: "risk-summary"
});

assert.equal(requirement.x402Version, 2);
assert.equal(requirement.resource.url, "https://mba.example/api/compute");
assert.equal(requirement.error, "PAYMENT-SIGNATURE header is required");
assert.ok(paymentRequirementId(requirement));
assert.deepEqual(Object.keys(requirement).sort(), [
  "accepts",
  "error",
  "extensions",
  "resource",
  "x402Version"
]);

const accepted = requirement.accepts[0];
assert.deepEqual(Object.keys(accepted).sort(), [
  "amount",
  "asset",
  "extra",
  "maxTimeoutSeconds",
  "network",
  "payTo",
  "scheme"
]);
assert.equal(accepted.network, "eip155:1");
assert.equal(accepted.amount, "50000");
assert.equal(
  accepted.asset,
  "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
);
assert.equal(accepted.extra.mba.railId, "ethereum");

const paymentPayload = {
  x402Version: 2,
  resource: requirement.resource,
  accepted,
  payload: {
    signature: "0xclient-signature",
    authorization: {
      from: "0x1111111111111111111111111111111111111111",
      to: accepted.payTo,
      value: accepted.amount,
      validAfter: "0",
      validBefore: "9999999999",
      nonce: `0x${"ab".repeat(32)}`
    }
  },
  extensions: requirement.extensions
};

const calls = [];
globalThis.fetch = async (url, init) => {
  const body = JSON.parse(init.body);
  calls.push({ url, init, body });
  assert.equal(init.method, "POST");
  assert.equal(init.headers["content-type"], "application/json");
  assert.equal(body.x402Version, 2);
  assert.deepEqual(body.paymentPayload, paymentPayload);
  assert.deepEqual(body.paymentRequirements, accepted);
  if (url.endsWith("/verify")) {
    return Response.json({
      isValid: true,
      payer: "0x1111111111111111111111111111111111111111"
    });
  }
  if (url.endsWith("/settle")) {
    return Response.json({
      success: true,
      payer: "0x1111111111111111111111111111111111111111",
      transaction: `0x${"cd".repeat(32)}`,
      network: accepted.network
    });
  }
  return Response.json({ error: "unexpected path" }, { status: 404 });
};

const settled = await verifyAndSettlePayment(requirement, paymentPayload);
assert.equal(settled.ok, true);
assert.equal(calls.length, 2);
assert.equal(calls[0].url, "https://facilitator.example/verify");
assert.equal(calls[1].url, "https://facilitator.example/settle");
assert.equal(settled.paymentReceipt.railId, "ethereum");
assert.equal(settled.paymentReceipt.networkId, "eip155:1");
assert.equal(settled.paymentReceipt.amount, "50000");
assert.equal(settled.paymentReceipt.mocked, false);
assert.equal(
  settled.paymentReceipt.txHash,
  `0x${"cd".repeat(32)}`
);
assert.deepEqual(
  Object.keys(buildPaymentResponse(settled.paymentReceipt)).sort(),
  ["amount", "extensions", "network", "payer", "success", "transaction"]
);

const tampered = structuredClone(paymentPayload);
tampered.accepted.amount = "1";
const beforeTamperCalls = calls.length;
const rejected = await verifyAndSettlePayment(requirement, tampered);
assert.equal(rejected.ok, false);
assert.match(rejected.reason, /does not match/i);
assert.equal(calls.length, beforeTamperCalls);

const missingExtension = structuredClone(paymentPayload);
delete missingExtension.extensions[MBA_X402_EXTENSION];
const missingExtensionResult = await verifyAndSettlePayment(
  requirement,
  missingExtension
);
assert.equal(missingExtensionResult.ok, false);
assert.match(missingExtensionResult.reason, /omitted.*extension/i);
assert.equal(calls.length, beforeTamperCalls);

assert.equal(
  requirement.extensions[MBA_X402_EXTENSION].info.serviceId,
  "agent-mission-bound-auth"
);

console.log(JSON.stringify({
  ok: true,
  protocol: "x402-v2",
  checks: [
    "standard PaymentRequired shape",
    "standard PaymentRequirements shape",
    "CAIP-2 network and atomic amount",
    "MBA extension placement",
    "facilitator /verify request",
    "facilitator /settle request",
    "settlement receipt binding",
    "standard SettlementResponse shape",
    "tampered requirement rejection",
    "challenge extension binding"
  ]
}, null, 2));
