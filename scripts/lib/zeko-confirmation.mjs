import { fetchAccount } from "o1js";
import { MissionRegistry } from "../../dist-zkapp/MissionRegistry.js";

const DEFAULT_TIMEOUT_MS = 120_000;
const DEFAULT_INTERVAL_MS = 2_000;

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function waitForAccountState(
  publicKey,
  predicate,
  {
    description = "account state update",
    timeoutMs = Number(
      process.env.ZEKO_CONFIRM_TIMEOUT_MS ?? DEFAULT_TIMEOUT_MS
    ),
    intervalMs = Number(
      process.env.ZEKO_CONFIRM_INTERVAL_MS ?? DEFAULT_INTERVAL_MS
    )
  } = {}
) {
  const deadline = Date.now() + timeoutMs;
  let lastError = null;

  while (Date.now() < deadline) {
    try {
      const fetched = await fetchAccount({ publicKey });
      if (!fetched.error && await predicate(fetched.account)) {
        return fetched.account;
      }
      lastError = fetched.error?.statusText ?? null;
    } catch (error) {
      lastError = error instanceof Error ? error.message : String(error);
    }
    await delay(intervalMs);
  }

  const suffix = lastError ? ` Last error: ${lastError}` : "";
  throw new Error(
    `Timed out waiting for ${description} at ${publicKey.toBase58()}.${suffix}`
  );
}

export function waitForRegistryState(
  registryAddress,
  { registryRoot, sequence, description = "MissionRegistry state update" }
) {
  return waitForAccountState(
    registryAddress,
    () => {
      const observed = new MissionRegistry(registryAddress);
      return observed.registryRoot.get().toString() === String(registryRoot) &&
        observed.sequence.get().toString() === String(sequence);
    },
    { description }
  );
}
