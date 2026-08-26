import { Field, MerkleMap } from "o1js";
import { canonicalize, sha256Hex } from "./digest.js";

export const ZEKO_ENCODING_VERSION = "mba-zeko-encoding-v1";

function assertCanonicalScalar(value, label) {
  if (
    value === undefined ||
    typeof value === "function" ||
    typeof value === "symbol" ||
    typeof value === "bigint"
  ) {
    throw new TypeError(`${label} is not canonical JSON.`);
  }
}

export function canonicalBytes(value) {
  assertCanonicalScalar(value, "value");
  return Buffer.from(
    typeof value === "string" ? value : canonicalize(value),
    "utf8"
  );
}

export function canonicalDigest(value) {
  return sha256Hex(canonicalBytes(value).toString("utf8"));
}

export function digestHexToField(digest) {
  if (!/^[0-9a-f]{64}$/i.test(String(digest ?? ""))) {
    throw new TypeError("digest must be a 32-byte hexadecimal SHA-256 value.");
  }
  return Field(BigInt(`0x${digest}`) % Field.ORDER);
}

export function canonicalValueToField(value) {
  return digestHexToField(canonicalDigest(value));
}

export function canonicalStringSet(values, label = "values") {
  if (!Array.isArray(values)) {
    throw new TypeError(`${label} must be an array.`);
  }
  return Array.from(new Set(values.map((value) => {
    if (typeof value !== "string" || value.length === 0) {
      throw new TypeError(`${label} must contain non-empty strings.`);
    }
    return value.normalize("NFC");
  }))).sort();
}

export function stringSetKey(namespace, value) {
  if (typeof namespace !== "string" || !namespace) {
    throw new TypeError("namespace must be a non-empty string.");
  }
  if (typeof value !== "string" || !value) {
    throw new TypeError("value must be a non-empty string.");
  }
  return canonicalValueToField({
    encoding: ZEKO_ENCODING_VERSION,
    namespace,
    value: value.normalize("NFC")
  });
}

export function buildStringSetMap(namespace, values) {
  const normalizedValues = canonicalStringSet(values);
  const map = new MerkleMap();
  for (const value of normalizedValues) {
    map.set(stringSetKey(namespace, value), Field(1));
  }
  return {
    map,
    values: normalizedValues,
    root: map.getRoot()
  };
}

export function parseDecimalToUnits(value, decimals, label = "amount") {
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 30) {
    throw new RangeError("decimals must be an integer between 0 and 30.");
  }
  const normalized = String(value ?? "").trim();
  if (!/^(0|[1-9][0-9]*)(\.[0-9]+)?$/.test(normalized)) {
    throw new TypeError(`${label} must be a non-negative decimal string.`);
  }
  const [whole, fraction = ""] = normalized.split(".");
  if (fraction.length > decimals) {
    throw new RangeError(`${label} has more than ${decimals} decimal places.`);
  }
  return (
    BigInt(whole) * (10n ** BigInt(decimals)) +
    BigInt((fraction + "0".repeat(decimals)).slice(0, decimals) || "0")
  );
}

export function formatUnits(value, decimals) {
  const amount = BigInt(value);
  if (amount < 0n) throw new RangeError("amount must be non-negative.");
  const scale = 10n ** BigInt(decimals);
  const whole = amount / scale;
  const fraction = (amount % scale).toString().padStart(decimals, "0");
  return decimals === 0
    ? whole.toString()
    : `${whole}.${fraction}`.replace(/\.?0+$/, "");
}

export function usdToMicrousd(value) {
  return parseDecimalToUnits(value, 6, "USD amount");
}

export function nativeToNanoUnits(value) {
  return parseDecimalToUnits(value, 9, "Zeko native amount");
}

// Retained for v1 proof and receipt code that uses the historical wire name.
export const minaToNanomina = nativeToNanoUnits;
