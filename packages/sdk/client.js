export class ZkMissionAuthClient {
  constructor({ baseUrl, fetchImpl = globalThis.fetch }) {
    if (!baseUrl) throw new Error("baseUrl is required.");
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.fetch = fetchImpl;
  }

  async json(path, options = {}) {
    const res = await this.fetch(`${this.baseUrl}${path}`, {
      ...options,
      headers: {
        "content-type": "application/json",
        ...(options.headers ?? {})
      }
    });
    const body = await res.json();
    if (!res.ok) {
      const error = new Error(body.reason ?? body.error ?? `HTTP ${res.status}`);
      error.status = res.status;
      error.body = body;
      throw error;
    }
    return body;
  }

  discover() {
    return this.json("/.well-known/agent-authorization.json");
  }

  jwks() {
    return this.json("/.well-known/mission-authority-jwks.json");
  }

  issueDemoProof(input = {}) {
    return this.json("/api/oauth/zk-issue", {
      method: "POST",
      body: JSON.stringify(input)
    });
  }

  createAgentPassport(input) {
    return this.json("/api/agents/passport", {
      method: "POST",
      body: JSON.stringify(input)
    });
  }

  proposeMission(input) {
    return this.json("/api/missions/propose", {
      method: "POST",
      body: JSON.stringify(input)
    });
  }

  approveMission(input) {
    return this.json("/api/missions/approve", {
      method: "POST",
      body: JSON.stringify(input)
    });
  }

  verifyCheckpoint(input) {
    return this.json("/api/mission/verify-checkpoint", {
      method: "POST",
      body: JSON.stringify(input)
    });
  }

  enforceCheckpoint(input, bearerToken) {
    return this.json("/api/mission/enforce-checkpoint", {
      method: "POST",
      headers: bearerToken ? { authorization: `Bearer ${bearerToken}` } : {},
      body: JSON.stringify(input)
    });
  }

  exportBundle(input) {
    return this.json("/api/mission/export-bundle", {
      method: "POST",
      body: JSON.stringify(input)
    });
  }

  requestCompute(input, paymentHeader) {
    return this.json("/api/compute", {
      method: "POST",
      headers: paymentHeader ? { "PAYMENT-SIGNATURE": paymentHeader } : {},
      body: JSON.stringify(input)
    });
  }

  authorizeMockPayment(input) {
    return this.json("/api/payments/mock-authorize", {
      method: "POST",
      body: JSON.stringify(input)
    });
  }
}
