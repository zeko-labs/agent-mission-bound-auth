#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import {
  verifyAnchorPayload,
  verifyExecutionBundle,
  verifyMissionComplianceProofArtifact,
  verifyProductionReceiptCryptographically,
  verifyProductionStrictReceipt,
  verifyReceipt,
  verifySettlementOnZeko,
  verifySettlementState,
  verifyTraceChain,
  verifyZekoRegistryAnchorOnChain
} from "../packages/sdk/index.js";

function usage() {
  return {
    valid: false,
    error: "usage",
    commands: [
      "mba verify receipt receipt.json",
      "mba verify receipt --production-strict receipt.json --verification-key verification-key.json --authority-jwks authority-jwks.json --domain-verifier verifier.mjs",
      "mba verify proof proof.json --verification-key verification-key.json",
      "mba verify zeko receipt.json anchor.json --verification-key verification-key.json --graphql https://sepolia.zeko.io/graphql",
      "mba verify bundle execution-bundle.json",
      "mba verify trace trace.json",
      "mba verify anchor receipt.json anchor.json",
      "mba verify settlement receipt.json anchor.json --verification-key verification-key.json --authority-jwks authority-jwks.json --domain-verifier verifier.mjs --graphql https://sepolia.zeko.io/graphql"
    ]
  };
}

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function readVerificationKey(file) {
  const value = readJson(file);
  return value.verificationKey ?? value;
}

function readAuthorityJwks(file) {
  if (!file) return null;
  const value = readJson(file);
  return value.jwks ?? value;
}

async function readDomainVerifier(file) {
  if (!file) return null;
  const module = await import(
    pathToFileURL(path.resolve(file)).href
  );
  const verifier =
    module.verifyDomainProof ?? module.default;
  if (typeof verifier !== "function") {
    throw new Error(
      "domain verifier module must export default or verifyDomainProof."
    );
  }
  return verifier;
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

function option(args, name) {
  const index = args.indexOf(name);
  return index >= 0 ? args[index + 1] : null;
}

const [, , command, subject, ...args] = process.argv;

try {
  if (command !== "verify") {
    print(usage(), 1);
  } else if (subject === "receipt") {
    const strict = args.includes("--production-strict");
    const receiptPath = args.find((arg) => !arg.startsWith("--") && arg !== option(args, "--verification-key") && arg !== option(args, "--circuit-digest"));
    const receipt = readJson(receiptPath);
    const verificationKeyPath = option(args, "--verification-key");
    const result = strict
      ? verificationKeyPath
        ? await verifyProductionReceiptCryptographically(receipt, {
            verificationKey: readVerificationKey(verificationKeyPath),
            circuitDigest: option(args, "--circuit-digest") ?? undefined,
            authorityJwks: readAuthorityJwks(
              option(args, "--authority-jwks")
            ),
            domainProofVerifier: await readDomainVerifier(
              option(args, "--domain-verifier")
            )
          })
        : {
            ...verifyProductionStrictReceipt(receipt),
            valid: false,
            reason: "production-strict receipt verification requires --verification-key."
          }
      : verifyReceipt(receipt);
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
  } else if (subject === "proof") {
    const artifact = readJson(args[0]);
    const verificationKeyPath = option(args, "--verification-key");
    if (!verificationKeyPath) {
      throw new Error("proof verification requires --verification-key.");
    }
    const result = await verifyMissionComplianceProofArtifact(artifact, {
      verificationKey: readVerificationKey(verificationKeyPath),
      circuitDigest: option(args, "--circuit-digest") ?? undefined
    });
    print(verifierReport({
      valid: result.valid,
      holderProofs: result.valid ? "valid_in_zk_proof" : "invalid",
      traceChain: result.valid ? "valid_in_zk_proof" : "invalid",
      policy: result.valid ? "valid_in_zk_proof" : "invalid",
      paymentBinding: result.valid ? "valid_in_zk_proof" : "invalid",
      proof: result.valid ? "valid" : "invalid",
      reason: result.reason
    }), result.valid ? 0 : 1);
  } else if (subject === "zeko") {
    const receipt = readJson(args[0]);
    const anchor = readJson(args[1]);
    const verificationKeyPath = option(args, "--verification-key");
    const graphql = option(args, "--graphql");
    if (!verificationKeyPath || !graphql) {
      throw new Error("Zeko verification requires --verification-key and --graphql.");
    }
    const result = await verifyZekoRegistryAnchorOnChain(receipt, anchor, {
      verificationKey: readVerificationKey(verificationKeyPath),
      circuitDigest: option(args, "--circuit-digest") ?? undefined,
      graphql,
      expectedRegistryAddress: option(args, "--registry") ?? undefined
    });
    print(verifierReport({
      valid: result.valid,
      holderProofs: result.valid ? "valid_in_zk_proof" : "invalid",
      traceChain: result.valid ? "valid_in_zk_proof" : "invalid",
      policy: result.valid ? "valid_in_zk_proof" : "invalid",
      paymentBinding: result.valid ? "valid_in_zk_proof" : "invalid",
      anchor: result.valid ? "valid_on_zeko" : "invalid",
      settlement: result.valid ? "proof_and_chain_verified" : "release_denied",
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
    const anchor = readJson(args[1]);
    const verificationKeyPath = option(args, "--verification-key");
    const graphql = option(args, "--graphql");
    if (!verificationKeyPath || !graphql) {
      throw new Error("settlement verification requires --verification-key and --graphql.");
    }
    const result = await verifySettlementOnZeko(receipt, anchor, {
      verificationKey: readVerificationKey(verificationKeyPath),
      circuitDigest: option(args, "--circuit-digest") ?? undefined,
      authorityJwks: readAuthorityJwks(
        option(args, "--authority-jwks")
      ),
      domainProofVerifier: await readDomainVerifier(
        option(args, "--domain-verifier")
      ),
      graphql,
      expectedRegistryAddress: option(args, "--registry") ?? undefined
    });
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
