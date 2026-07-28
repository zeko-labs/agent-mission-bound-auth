import { decodeJson, encodeJson, hmacSha256Hex, id, sha256Hex } from "./digest.js";
import { enabledRails, findRail } from "./rails.js";
import {
  isProductionProfile,
  isSettlementEnabled
} from "./runtime.js";

export const PAYMENT_REQUIRED = "PAYMENT-REQUIRED";
export const PAYMENT_SIGNATURE = "PAYMENT-SIGNATURE";
export const PAYMENT = PAYMENT_SIGNATURE;
export const PAYMENT_RESPONSE = "PAYMENT-RESPONSE";
export const MBA_X402_EXTENSION = "agent-mission-bound-auth";

function baseUrl() {
  return process.env.BASE_URL ?? `http://${process.env.HOST ?? "127.0.0.1"}:${process.env.PORT ?? "8787"}`;
}

function paymentSecret() {
  return process.env.X402_DEMO_PAYMENT_SECRET ?? "local-x402-payment-secret";
}

function buildAuthorizationDigest(payload) {
  return sha256Hex(payload);
}

function stripAuthorizationDigest(payload) {
  const {
    authorizationDigest: _authorizationDigest,
    settlementProof: _settlementProof,
    facilitatorReceipt: _facilitatorReceipt,
    ...rest
  } = payload;
  return rest;
}

function sameAsset(expected, actual) {
  if (actual === undefined || actual === null) return false;
  try {
    return sha256Hex(expected) === sha256Hex(actual);
  } catch {
    return false;
  }
}

function extensionSchema() {
  return {
    type: "object",
    required: ["requestId", "serviceId"],
    properties: {
      requestId: { type: "string" },
      serviceId: { type: "string" },
      outputType: { type: "string" },
      proofBundleUrl: { type: "string" },
      verifyUrl: { type: "string" }
    }
  };
}

function publicRequirement(rail) {
  return {
    scheme: "exact",
    network: rail.network,
    amount: rail.amount,
    asset: rail.assetId,
    payTo: rail.payTo,
    maxTimeoutSeconds: 60,
    extra: {
      ...(rail.asset?.symbol ? { name: rail.asset.symbol } : {}),
      ...(rail.asset?.symbol === "USDC" ? { version: "2" } : {}),
      mba: {
        railId: rail.id,
        settlementRail: rail.settlementRail,
        chainName: rail.chainName,
        settlementModel: rail.settlementModel,
        asset: rail.asset,
        preview: rail.preview,
        extensions: rail.extensions ?? {}
      }
    }
  };
}

export function paymentRequirementId(requirement) {
  return requirement?.extensions?.[MBA_X402_EXTENSION]?.info?.requestId ?? null;
}

export function paymentRailId(paymentPayload) {
  return (
    paymentPayload?.accepted?.extra?.mba?.railId ??
    paymentPayload?.extensions?.[MBA_X402_EXTENSION]?.info?.railId ??
    paymentPayload?.railId ??
    null
  );
}

function buildPaymentRequired(input) {
  const accepts = input.rails.map(publicRequirement);
  const requestId = id("x402req", {
    serviceId: input.serviceId,
    sessionId: input.sessionId,
    turnId: input.turnId,
    accepts
  });
  return {
    x402Version: 2,
    error: "PAYMENT-SIGNATURE header is required",
    resource: {
      url: `${input.baseUrl}/api/compute`,
      description: input.description,
      mimeType: "application/json"
    },
    accepts,
    extensions: {
      [MBA_X402_EXTENSION]: {
        info: {
          requestId,
          serviceId: input.serviceId,
          outputType: input.outputType,
          proofBundleUrl: input.proofBundleUrl,
          verifyUrl: input.verifyUrl
        },
        schema: extensionSchema()
      }
    }
  };
}

export function buildPaymentRequirement(job) {
  const rails = enabledRails();
  if (rails.length === 0) {
    throw new Error("No production x402 settlement rails are configured.");
  }
  const requirement = buildPaymentRequired({
    serviceId: "agent-mission-bound-auth",
    baseUrl: baseUrl(),
    sessionId: job.jobId,
    turnId: job.operation,
    description: "Exact-price private compute over committed data with ZK-backed OAuth authorization.",
    outputType: "private-compute-receipt-v1",
    verifyUrl: `${baseUrl()}/api/x402/verify`,
    proofBundleUrl: `${baseUrl()}/api/compute/receipt`,
    rails
  });

  const upstreamRequestId = paymentRequirementId(requirement);
  requirement.extensions[MBA_X402_EXTENSION].info.requestId = id("req", {
    upstreamRequestId,
    jobId: job.jobId,
    datasetId: job.datasetId,
    operation: job.operation
  });
  return requirement;
}

export function encodeRequirement(requirement) {
  return encodeJson(requirement);
}

export function decodePaymentHeader(header) {
  if (!header) return null;
  return decodeJson(header);
}

export function buildMockPayment(requirement, railId, payer = "demo-agent-wallet") {
  if (isProductionProfile()) {
    throw new Error("Mock x402 payments are disabled in production profile.");
  }
  const option = requirement.accepts.find((item) => item.extra?.mba?.railId === railId);
  if (!option) {
    throw new Error(`Unknown rail ${railId}`);
  }

  const issuedAtIso = new Date().toISOString();
  const expiresAtIso = new Date(Date.now() + 10 * 60 * 1000).toISOString();
  const requestId = paymentRequirementId(requirement);
  const mba = {
    requestId,
    paymentId: id("pay", { requestId, railId, payer, issuedAtIso }),
    scheme: "exact",
    settlementRail: option.extra.mba.settlementRail,
    railId,
    networkId: option.network,
    asset: option.asset,
    amount: option.amount,
    payer,
    payTo: option.payTo,
    sessionId: "demo-session",
    issuedAtIso,
    expiresAtIso,
  };
  const unsigned = {
    x402Version: 2,
    resource: requirement.resource,
    accepted: option,
    payload: {
      authorization: {
        primitive: option.extra.mba.settlementRail === "zeko"
          ? "zeko-signed-settlement-v1"
          : "eip3009-authorization-v1",
        settlementRail: option.extra.mba.settlementRail,
        mode: "mock-facilitator",
        authorizationHash: sha256Hex({ option, payer, issuedAtIso })
      }
    },
    extensions: {
      ...requirement.extensions,
      [MBA_X402_EXTENSION]: {
        ...requirement.extensions[MBA_X402_EXTENSION],
        info: {
          ...requirement.extensions[MBA_X402_EXTENSION].info,
          ...mba
        }
      }
    }
  };
  const authorizationDigest = buildAuthorizationDigest(unsigned);
  const payload = {
    ...unsigned,
    extensions: {
      ...unsigned.extensions,
      [MBA_X402_EXTENSION]: {
        ...unsigned.extensions[MBA_X402_EXTENSION],
        info: {
          ...unsigned.extensions[MBA_X402_EXTENSION].info,
          authorizationDigest
        }
      }
    }
  };

  return {
    payload,
    paymentHeader: encodeJson(payload),
    signature: hmacSha256Hex(paymentSecret(), payload)
  };
}

function normalizePayment(payment) {
  if (payment?.x402Version === 2 && payment.accepted && payment.payload) {
    const mba = payment.extensions?.[MBA_X402_EXTENSION]?.info ?? {};
    return {
      ...mba,
      scheme: payment.accepted.scheme,
      settlementRail:
        payment.accepted.extra?.mba?.settlementRail ??
        (String(payment.accepted.network).startsWith("eip155:")
          ? "evm"
          : null),
      railId:
        payment.accepted.extra?.mba?.railId,
      networkId: payment.accepted.network,
      asset: payment.accepted.asset,
      amount: payment.accepted.amount,
      payTo: payment.accepted.payTo,
      authorization: payment.payload.authorization,
      settlementProof:
        payment.settlementProof ?? mba.settlementProof,
      facilitatorReceipt:
        payment.facilitatorReceipt ?? mba.facilitatorReceipt,
      x402Envelope: payment
    };
  }
  return payment;
}

function verifySettlementProof(option, payment) {
  if (!isProductionProfile()) return { ok: true, mode: "demo" };
  return {
    ok: false,
    reason: "Production x402 requires async facilitator verification and settlement."
  };
}

function facilitatorUrl(pathname) {
  const base = process.env.X402_FACILITATOR_URL;
  if (!base) {
    throw new Error("X402_FACILITATOR_URL is required for live x402 settlement.");
  }
  return `${base.replace(/\/$/, "")}/${pathname.replace(/^\//, "")}`;
}

async function callFacilitator(pathname, body) {
  const response = await fetch(facilitatorUrl(pathname), {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(process.env.X402_FACILITATOR_AUTHORIZATION
        ? { authorization: process.env.X402_FACILITATOR_AUTHORIZATION }
        : {})
    },
    body: JSON.stringify(body)
  });
  const result = await response.json();
  if (!response.ok) {
    throw new Error(
      result.invalidReason ??
      result.error ??
      `x402 facilitator ${pathname} failed with ${response.status}.`
    );
  }
  return result;
}

function matchingOfficialRequirement(requirement, paymentPayload) {
  if (paymentPayload?.x402Version !== 2) return null;
  return requirement.accepts.find(
    (candidate) => sha256Hex(candidate) === sha256Hex(paymentPayload.accepted)
  ) ?? null;
}

function paymentPayloadMatchesChallenge(requirement, paymentPayload) {
  if (
    paymentPayload.resource &&
    sha256Hex(paymentPayload.resource) !== sha256Hex(requirement.resource)
  ) {
    return { ok: false, reason: "x402 v2 payment resource does not match this challenge." };
  }
  const requiredInfo =
    requirement.extensions?.[MBA_X402_EXTENSION]?.info ?? {};
  const suppliedInfo =
    paymentPayload.extensions?.[MBA_X402_EXTENSION]?.info;
  if (!suppliedInfo) {
    return { ok: false, reason: "x402 v2 payment omitted the MBA challenge extension." };
  }
  for (const [key, value] of Object.entries(requiredInfo)) {
    if (sha256Hex(suppliedInfo[key]) !== sha256Hex(value)) {
      return {
        ok: false,
        reason: `x402 v2 payment changed MBA challenge field ${key}.`
      };
    }
  }
  return { ok: true };
}

export function buildPaymentResponse(paymentReceipt) {
  return {
    success: true,
    transaction: paymentReceipt.txHash,
    network: paymentReceipt.networkId,
    payer: paymentReceipt.payer,
    amount: paymentReceipt.amount,
    extensions: {
      [MBA_X402_EXTENSION]: {
        info: {
          requestId: paymentReceipt.requestId,
          paymentId: paymentReceipt.paymentId,
          railId: paymentReceipt.railId
        },
        schema: {
          type: "object",
          required: ["requestId", "paymentId", "railId"],
          properties: {
            requestId: { type: "string" },
            paymentId: { type: "string" },
            railId: { type: "string" }
          }
        }
      }
    }
  };
}

export async function verifyAndSettlePayment(requirement, paymentPayload) {
  if (!isProductionProfile()) {
    return verifyPayment(requirement, paymentPayload);
  }
  if (!isSettlementEnabled()) {
    return {
      ok: false,
      reason: "x402 settlement is disabled by MISSION_SETTLEMENT_PROFILE."
    };
  }
  const accepted = matchingOfficialRequirement(
    requirement,
    paymentPayload
  );
  if (!accepted) {
    return {
      ok: false,
      reason: "x402 v2 payment accepted requirement does not match this challenge."
    };
  }
  const challengeMatch = paymentPayloadMatchesChallenge(
    requirement,
    paymentPayload
  );
  if (!challengeMatch.ok) return challengeMatch;
  const request = {
    x402Version: 2,
    paymentPayload,
    paymentRequirements: accepted
  };
  let verification;
  let settlement;
  try {
    verification = await callFacilitator("verify", request);
    if (verification.isValid !== true) {
      return {
        ok: false,
        reason: verification.invalidReason ?? "x402 facilitator rejected payment."
      };
    }
    settlement = await callFacilitator("settle", request);
  } catch (error) {
    return {
      ok: false,
      reason: error instanceof Error ? error.message : "x402 facilitator failed."
    };
  }
  if (
    settlement.success !== true ||
    !settlement.transaction
  ) {
    return {
      ok: false,
      reason: settlement.errorReason ?? "x402 settlement failed."
    };
  }
  if (settlement.network !== accepted.network) {
    return { ok: false, reason: "x402 settlement network mismatch." };
  }
  if (
    settlement.amount !== undefined &&
    settlement.amount !== accepted.amount
  ) {
    return { ok: false, reason: "x402 settlement amount mismatch." };
  }
  if (
    verification.payer &&
    settlement.payer &&
    verification.payer !== settlement.payer
  ) {
    return { ok: false, reason: "x402 facilitator payer mismatch." };
  }
  const payer = settlement.payer ?? verification.payer;
  if (!payer) {
    return { ok: false, reason: "x402 facilitator did not identify payer." };
  }
  const paymentContextDigest = sha256Hex({
    paymentPayload,
    accepted,
    payer,
    transaction: settlement.transaction
  });
  return {
    ok: true,
    rail: findRail(accepted.extra?.mba?.railId ?? accepted.network),
    facilitatorVerification: verification,
    facilitatorSettlement: settlement,
    paymentReceipt: {
      paymentId:
        paymentPayload.extensions?.["payment-identifier"]?.info?.id ??
        id("x402pay", paymentPayload),
      requestId: paymentRequirementId(requirement),
      railId: accepted.extra?.mba?.railId ?? accepted.network,
      networkId: accepted.network,
      amount: accepted.amount,
      asset: accepted.asset,
      payer,
      payTo: accepted.payTo,
      authorizationDigest: paymentContextDigest,
      txHash: settlement.transaction,
      settledAt: new Date().toISOString(),
      mocked: false
    }
  };
}

export function verifyPayment(requirement, payment) {
  if (isProductionProfile()) {
    return {
      ok: false,
      reason: isSettlementEnabled()
        ? "Production x402 requires verifyAndSettlePayment()."
        : "x402 settlement is disabled by MISSION_SETTLEMENT_PROFILE."
    };
  }
  payment = normalizePayment(payment);
  if (!payment || typeof payment !== "object") {
    return { ok: false, reason: "Missing x402 payment payload." };
  }

  const option = requirement.accepts.find((item) => (
    item.extra?.mba?.railId === payment.railId &&
    item.extra?.mba?.settlementRail === payment.settlementRail &&
    item.network === payment.networkId &&
    item.amount === payment.amount &&
    sameAsset(item.asset, payment.asset) &&
    item.payTo === payment.payTo
  ));

  if (!option) {
    return { ok: false, reason: "Payment does not match any advertised x402 rail." };
  }

  if (payment.requestId !== paymentRequirementId(requirement)) {
    return { ok: false, reason: "Payment requestId does not match the requirement." };
  }

  const paymentExpiry = Date.parse(payment.expiresAtIso);
  if (Number.isNaN(paymentExpiry) || paymentExpiry <= Date.now()) {
    return { ok: false, reason: "Payment authorization has expired or has invalid expiry." };
  }

  const digestBody = payment.x402Envelope
    ? {
        ...payment.x402Envelope,
        extensions: {
          ...payment.x402Envelope.extensions,
          [MBA_X402_EXTENSION]: {
            ...payment.x402Envelope.extensions?.[MBA_X402_EXTENSION],
            info: stripAuthorizationDigest(
              payment.x402Envelope.extensions?.[MBA_X402_EXTENSION]?.info ?? {}
            )
          }
        }
      }
    : stripAuthorizationDigest(payment);
  const expectedDigest = buildAuthorizationDigest(digestBody);
  if (expectedDigest !== payment.authorizationDigest) {
    return { ok: false, reason: "Payment authorization digest is invalid." };
  }
  const settlementProof = verifySettlementProof(option, payment);
  if (!settlementProof.ok) {
    return settlementProof;
  }

  return {
    ok: true,
    rail: findRail(payment.railId),
    settlementProof: settlementProof.proof ?? null,
    paymentReceipt: {
      paymentId: payment.paymentId,
      requestId: payment.requestId,
      railId: payment.railId,
      networkId: payment.networkId,
      amount: payment.amount,
      asset: payment.asset,
      payer: payment.payer,
      payTo: payment.payTo,
      authorizationDigest: payment.authorizationDigest,
      txHash: settlementProof.proof?.txHash ?? `0x${sha256Hex({ payment, settledAt: "mock-stable" }).slice(0, 64)}`,
      settledAt: new Date().toISOString(),
      mocked: !isProductionProfile()
    }
  };
}
