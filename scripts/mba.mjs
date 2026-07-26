#!/usr/bin/env node
import fs from "node:fs";
import {
  verifyAnchorPayload,
  verifyExecutionBundle,
  verifyProductionStrictReceipt,
  verifyReceipt,
  verifySettlementState,
  verifyTraceChain
} from "../packages/sdk/index.js";

function usage() {
  return {
    valid: false,
    error: "usage",
    commands: [
      "mba verify receipt receipt.json",
      "mba verify receipt --production-strict receipt.json",
      "mba verify bundle execution-bundle.json",
      "mba verify trace trace.json",
      "mba verify anchor receipt.json anchor.json",
      "mba verify settlement receipt.json --registry settlement.json"
    ]
  };
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function verifierReport(overrides = {}) {
  return {
    valid: true,
    capability: "not_checked",
    holderProofs: "not_checked",
    traceChain: "not_checked",
    policy: "not_checked",
    paymentBinding: "not_checked",
    anchor: "not_checked",
    settlement: "not_checked",
    ...overrides
  };
}

function print(value, status = 0) {
  process.stdout.write(`${JSON.stringify(value, null, 2)}\n`);
  process.exitCode = status;
}

const [, , command, subject, ...args] = process.argv;

try {
  if (command !== "verify") {
    print(usage(), 1);
  } else if (subject === "receipt") {
    const strict = args[0] === "--production-strict";
    const receipt = readJson(strict ? args[1] : args[0]);
    const result = strict ? verifyProductionStrictReceipt(receipt) : verifyReceipt(receipt);
    print(verifierReport({
      valid: result.valid,
      capability: result.valid ? "valid" : "invalid",
      traceChain: result.valid ? "valid" : "invalid",
      policy: result.valid ? "valid" : "invalid",
      paymentBinding: result.valid ? "valid" : "invalid",
      anchor: receipt.anchor ? "valid" : "not_ready",
      settlement: result.settlementState ?? "not_ready",
      reason: result.reason
    }), result.valid ? 0 : 1);
  } else if (subject === "bundle") {
    const bundle = readJson(args[0]);
    const result = verifyExecutionBundle(bundle);
    print(verifierReport({
      valid: result.valid,
      capability: result.valid ? "valid" : "invalid",
      holderProofs: result.valid ? "valid" : "invalid",
      traceChain: result.valid ? "valid" : "invalid",
      policy: result.valid ? "valid" : "invalid",
      paymentBinding: result.valid ? "valid" : "invalid",
      anchor: bundle.zekoAnchor ? "valid" : "not_ready",
      settlement: bundle.settlement?.state ?? bundle.receipt?.settlementState ?? "not_ready",
      bundleHash: result.bundleHash,
      reason: result.reason
    }), result.valid ? 0 : 1);
  } else if (subject === "trace") {
    const trace = readJson(args[0]);
    const events = Array.isArray(trace) ? trace : trace.events;
    const result = verifyTraceChain(events, trace.options ?? {});
    print(verifierReport({
      valid: result.valid,
      holderProofs: result.valid ? "valid" : "invalid",
      traceChain: result.valid ? "valid" : "invalid",
      traceHash: result.traceHash,
      latestEventHash: result.latestEventHash,
      reason: result.reason
    }), result.valid ? 0 : 1);
  } else if (subject === "anchor") {
    const receipt = readJson(args[0]);
    const anchor = readJson(args[1]);
    const result = verifyAnchorPayload(receipt, anchor);
    print(verifierReport({
      valid: result.valid,
      capability: result.valid ? "valid" : "invalid",
      policy: result.valid ? "valid" : "invalid",
      paymentBinding: result.valid ? "valid" : "invalid",
      anchor: result.valid ? "valid" : "invalid",
      settlement: result.valid ? "anchor_verified" : "release_denied",
      reason: result.reason
    }), result.valid ? 0 : 1);
  } else if (subject === "settlement") {
    const receipt = readJson(args[0]);
    const registryIndex = args.indexOf("--registry");
    const settlement = registryIndex >= 0 ? readJson(args[registryIndex + 1]) : {};
    const result = verifySettlementState(receipt, settlement);
    print(verifierReport({
      valid: result.valid,
      capability: result.valid ? "valid" : "invalid",
      policy: result.valid ? "valid" : "invalid",
      paymentBinding: result.valid ? "valid" : "invalid",
      anchor: receipt.anchor ? "valid" : "not_ready",
      settlement: result.decision,
      reason: result.reason
    }), result.valid ? 0 : 1);
  } else {
    print(usage(), 1);
  }
} catch (error) {
  print({
    valid: false,
    error: error instanceof Error ? error.message : String(error)
  }, 1);
}
