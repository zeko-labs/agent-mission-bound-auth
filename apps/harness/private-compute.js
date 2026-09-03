import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { id, sha256Hex } from "../../packages/protocol/digest.js";
import { isProductionProfile } from "../../packages/protocol/runtime.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DATASET_PATH = path.join(__dirname, "..", "..", "data", "private-datasets.json");

export async function loadDatasets() {
  return JSON.parse(await fs.readFile(DATASET_PATH, "utf8"));
}

export function datasetCommitment(dataset) {
  return sha256Hex({
    id: dataset.id,
    owner: dataset.owner,
    title: dataset.title,
    classification: dataset.classification,
    records: dataset.records
  });
}

export function buildPolicy(dataset, operation) {
  return {
    version: "private-compute-policy-v1",
    datasetId: dataset.id,
    operation,
    requiredScopes: [...dataset.allowedScopes],
    minCohortSize: Number(process.env.PRIVATE_COMPUTE_MIN_COHORT ?? (isProductionProfile() ? 3 : 2)),
    disclosure: "aggregate-output-only",
    rawDataEgress: false
  };
}

function scoreRecord(record, query) {
  const terms = query.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  const text = record.toLowerCase();
  return terms.reduce((sum, term) => sum + (text.includes(term) ? 1 : 0), 0);
}

export function runPrivateCompute({ dataset, query, operation, auth, paymentReceipt, mission }) {
  const ranked = dataset.records
    .map((record) => ({ record, score: scoreRecord(record, query) }))
    .sort((a, b) => b.score - a.score);
  const relevant = ranked.filter((item) => item.score > 0);
  const basis = relevant.length > 0 ? relevant : ranked.slice(0, 2);
  const policy = buildPolicy(dataset, operation);
  const cohortMeetsPolicy = basis.length >= policy.minCohortSize;
  const joined = basis.map((item) => item.record).join(" ");
  const themes = cohortMeetsPolicy ? Array.from(
    new Set(
      joined
        .toLowerCase()
        .split(/[^a-z0-9]+/)
        .filter((word) => word.length > 6)
    )
  ).slice(0, 8) : [];

  const answer =
    !cohortMeetsPolicy
      ? `Private compute found ${basis.length} matching private records, below the minimum cohort threshold of ${policy.minCohortSize}. The result is withheld to preserve aggregate-only disclosure.`
      : operation === "risk-summary"
      ? `Private compute found ${basis.length} relevant private records. Dominant risk themes: ${themes.join(", ") || "none"}. The result is aggregate-only; raw records remain sealed.`
      : `Private compute completed over ${dataset.title}. The sealed dataset produced ${basis.length} relevant signals for the request.`;

  const output = {
    answer,
    aggregate: {
      recordsEvaluated: dataset.records.length,
      relevantSignals: cohortMeetsPolicy ? basis.length : 0,
      dominantThemes: themes,
      confidence: cohortMeetsPolicy && basis.some((item) => item.score > 1) ? "high" : "medium",
      minCohortSize: policy.minCohortSize,
      withheldForCohortPolicy: !cohortMeetsPolicy
    }
  };

  const receipt = {
    receiptId: id("rcpt", {
      datasetId: dataset.id,
      query,
      operation,
      authCommitment: auth.authCommitment,
      paymentId: paymentReceipt.paymentId
    }),
    datasetCommitment: datasetCommitment(dataset),
    policyHash: sha256Hex(policy),
    authCommitment: auth.authCommitment,
    scopeCommitment: auth.scopeCommitment,
    paymentContextDigest: paymentReceipt.authorizationDigest,
    missionId: mission?.missionId ?? null,
    missionHash: mission?.missionHash ?? null,
    missionCommitment: mission?.missionCommitment ?? null,
    enforcementReceipts: mission?.enforcementReceipts ?? [],
    outputHash: sha256Hex(output),
    paymentReceipt,
    zekoAuditReceipt: {
      networkId: "zeko:sepolia",
      protocolNetworkId: "zeko:sepolia",
      graphqlNetworkId: "zeko:testnet",
      signingNetworkId: "testnet",
      primitive: "private-compute-audit-receipt-v1",
      receiptCommitment: sha256Hex({
        datasetCommitment: datasetCommitment(dataset),
        policyHash: sha256Hex(policy),
        authCommitment: auth.authCommitment,
        missionHash: mission?.missionHash ?? null,
        outputHash: sha256Hex(output),
        paymentId: paymentReceipt.paymentId
      }),
      explorerHint: "https://zekoscan.io/testnet",
      mocked: true
    }
  };

  return { output, policy, receipt };
}
