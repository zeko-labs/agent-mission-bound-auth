import { createAuth0Client } from "/vendor/auth0-spa-js.production.esm.js";

const state = {
  proof: null,
  agentPassport: null,
  missionApproval: null,
  rails: [],
  selectedRail: "zeko",
  lastRequirement: null,
  auth0: {
    client: null,
    config: null,
    user: null,
    commitment: null
  }
};

const $ = (id) => document.getElementById(id);

async function json(path, options = {}) {
  const res = await fetch(path, {
    ...options,
    headers: {
      "content-type": "application/json",
      ...(options.headers ?? {})
    }
  });
  const body = await res.json();
  return { res, body };
}

function renderRails() {
  $("rails").innerHTML = state.rails
    .map((rail) => `
      <button class="rail ${rail.id === state.selectedRail ? "active" : ""}" data-rail="${rail.id}">
        <span>${rail.chainName}${rail.preview ? " (preview)" : ""}<small>${rail.asset.symbol} · ${rail.network}</small></span>
        <strong>${rail.displayAmount ?? rail.amount}</strong>
      </button>
    `)
    .join("");
  document.querySelectorAll(".rail").forEach((button) => {
    button.addEventListener("click", () => {
      state.selectedRail = button.dataset.rail;
      renderRails();
    });
  });
}

function renderResult(payload) {
  const receipt = payload.receipt;
  $("result").className = "";
  $("result").innerHTML = `
    <div class="receipt">
      <div class="answer">${payload.result.answer}</div>
      <div class="metric"><strong>Records evaluated</strong>${payload.result.aggregate.recordsEvaluated}</div>
      <div class="metric"><strong>Relevant signals</strong>${payload.result.aggregate.relevantSignals}</div>
      <div class="metric"><strong>Confidence</strong>${payload.result.aggregate.confidence}</div>
      <div class="metric"><strong>Raw data released</strong>${payload.rawDataReleased}</div>
      <div class="hashes">
        <div class="hash"><strong>Receipt</strong> ${receipt.receiptId}</div>
        <div class="hash"><strong>Dataset commitment</strong> ${receipt.datasetCommitment}</div>
        <div class="hash"><strong>Auth commitment</strong> ${receipt.authCommitment}</div>
        <div class="hash"><strong>Output hash</strong> ${receipt.outputHash}</div>
      <div class="hash"><strong>Payment</strong> ${receipt.paymentReceipt.railId} · ${receipt.paymentReceipt.txHash}</div>
        <div class="hash"><strong>Mission</strong> ${receipt.missionId} · ${receipt.missionHash}</div>
        <div class="hash"><strong>Zeko audit commitment</strong> ${receipt.zekoAuditReceipt.receiptCommitment}</div>
      </div>
    </div>
  `;
}

async function init() {
  const health = await json("/api/health").catch(() => null);
  $("health").textContent = health?.body?.ok ? "online" : "offline";
  $("health").className = `health ${health?.body?.ok ? "ok" : "bad"}`;

  const [{ body: railsBody }, { body: datasetsBody }] = await Promise.all([
    json("/api/rails"),
    json("/api/datasets")
  ]);
  state.rails = railsBody.rails;
  if (!state.rails.some((rail) => rail.id === state.selectedRail)) {
    state.selectedRail = state.rails[0]?.id ?? "zeko";
  }
  renderRails();

  $("dataset").innerHTML = datasetsBody.datasets
    .map((dataset) => `<option value="${dataset.id}">${dataset.title} · ${dataset.classification}</option>`)
    .join("");

  await initAuth0();
}

async function initAuth0() {
  try {
    const { body: config } = await json("/api/oauth/browser-config");
    state.auth0.config = config;
    if (!config.configured) {
      $("auth0Status").textContent = "Add Auth0 env vars";
      $("auth0Status").className = "status pending";
      $("auth0Profile").innerHTML = `
        <div class="hint">Set <strong>AUTH0_DOMAIN</strong> and <strong>AUTH0_CLIENT_ID</strong> in .env.local.</div>
      `;
      $("auth0Login").disabled = true;
      return;
    }

    state.auth0.client = await createAuth0Client({
      domain: config.domain,
      clientId: config.clientId,
      cacheLocation: "localstorage",
      useRefreshTokens: true,
      authorizationParams: {
        redirect_uri: window.location.origin,
        audience: config.audience || undefined,
        scope: "openid profile email compute:clinical dataset:clinical-failures-q1 rail:zeko rail:base budget:small"
      }
    });

    if (window.location.search.includes("code=") && window.location.search.includes("state=")) {
      await state.auth0.client.handleRedirectCallback();
      window.history.replaceState({}, document.title, window.location.pathname);
    }

    await updateAuth0Ui();
  } catch (error) {
    $("auth0Status").textContent = "Auth0 error";
    $("auth0Status").className = "status bad";
    $("auth0Profile").textContent = error instanceof Error ? error.message : String(error);
  }
}

async function updateAuth0Ui() {
  const isAuthenticated = await state.auth0.client.isAuthenticated();
  $("auth0Login").hidden = isAuthenticated;
  $("auth0Logout").hidden = !isAuthenticated;

  if (!isAuthenticated) {
    $("auth0Status").textContent = "Ready";
    $("auth0Status").className = "status pending";
    $("auth0Profile").innerHTML = `<div class="hint">Auth0 SPA login is configured.</div>`;
    return;
  }

  const user = await state.auth0.client.getUser();
  state.auth0.user = user;
  $("auth0Status").textContent = "Authenticated";
  $("auth0Status").className = "status ok";
  $("auth0Profile").innerHTML = `
    <div class="auth0-user">
      <img src="${user.picture ?? ""}" alt="" />
      <div>
        <strong>${user.name ?? user.email ?? user.sub}</strong>
        <span>${user.email ?? user.sub}</span>
      </div>
    </div>
  `;

  await commitAuth0Token();
}

async function commitAuth0Token() {
  const config = state.auth0.config;
  let token;
  let audience;
  try {
    if (config.audience) {
      token = await state.auth0.client.getTokenSilently({
        authorizationParams: {
          audience: config.audience,
          scope: "openid profile email compute:clinical dataset:clinical-failures-q1 rail:zeko rail:base budget:small"
        }
      });
      audience = config.audience;
    } else {
      const claims = await state.auth0.client.getIdTokenClaims();
      token = claims?.__raw;
      audience = config.clientId;
    }
    if (!token) return;
    const { body, res } = await json("/api/oauth/zk-commit", {
      method: "POST",
      body: JSON.stringify({
        provider: "auth0-spa",
        token,
        issuer: config.issuer,
        audience,
        jwksUrl: `${config.issuer}.well-known/jwks.json`,
        salt: "auth0-spa-local-salt"
      })
    });
    if (!res.ok) throw new Error(body.message ?? body.error ?? "commit failed");
    state.auth0.commitment = body;
    $("auth0Profile").insertAdjacentHTML("beforeend", `
      <div class="commitment">
        <strong>Auth commitment</strong>
        <span>${body.authCommitment}</span>
      </div>
    `);
  } catch (error) {
    $("auth0Profile").insertAdjacentHTML("beforeend", `
      <div class="hint warn">Authenticated, but token commitment failed: ${error instanceof Error ? error.message : String(error)}</div>
    `);
  }
}

$("issueProof").addEventListener("click", async () => {
  const { body } = await json("/api/oauth/zk-issue", { method: "POST", body: JSON.stringify({}) });
  state.proof = body.zkOAuthProof;
  const passport = await json("/api/agents/passport", {
    method: "POST",
    body: JSON.stringify({
      agentId: state.proof.revealed.agentId,
      organization: state.proof.revealed.organization
    })
  });
  state.agentPassport = passport.body.agentPassport;
  $("agentStatus").textContent = `${state.proof.revealed.agentId} verified`;
  $("agentStatus").className = "status ok";
});

$("auth0Login").addEventListener("click", async () => {
  if (!state.auth0.client) return;
  await state.auth0.client.loginWithRedirect({
    authorizationParams: {
      redirect_uri: window.location.origin,
      audience: state.auth0.config.audience || undefined,
      scope: "openid profile email compute:clinical dataset:clinical-failures-q1 rail:zeko rail:base budget:small"
    }
  });
});

$("auth0Logout").addEventListener("click", async () => {
  if (!state.auth0.client) return;
  await state.auth0.client.logout({
    logoutParams: {
      returnTo: window.location.origin
    }
  });
});

$("computeForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!state.proof) {
    $("agentStatus").textContent = "Issue proof first";
    $("agentStatus").className = "status bad";
    return;
  }

  const requestBody = {
    datasetId: $("dataset").value,
    operation: $("operation").value,
    query: $("query").value,
    zkOAuthProof: state.proof
  };

  const mission = await json("/api/missions/propose", {
    method: "POST",
    body: JSON.stringify({
      agentId: state.proof.revealed.agentId,
      datasetId: requestBody.datasetId,
      operation: requestBody.operation,
      task: requestBody.query,
      title: "Private compute risk summary",
      allowedScopes: [
        `compute:${requestBody.datasetId.split("-")[0]}`,
        `dataset:${requestBody.datasetId}`,
        "x402:pay"
      ],
      allowedRails: ["zeko", "ethereum", "base", "arc", "tempo"]
    })
  });
  const approval = await json("/api/missions/approve", {
    method: "POST",
    body: JSON.stringify({
      missionId: mission.body.mission.missionId,
      approverId: "enterprise-policy@example.com",
      issuer: "demo-enterprise-sso"
    })
  });
  state.missionApproval = approval.body.approval;
  requestBody.missionApproval = state.missionApproval;

  const first = await json("/api/compute", {
    method: "POST",
    body: JSON.stringify(requestBody)
  });
  state.lastRequirement = first.body.requirement;
  $("offer").textContent = JSON.stringify(first.body.requirement, null, 2);

  const payment = await json("/api/payments/mock-authorize", {
    method: "POST",
    body: JSON.stringify({
      requirement: state.lastRequirement,
      railId: state.selectedRail,
      payer: state.proof.revealed.agentId
    })
  });

  const paid = await json("/api/compute", {
    method: "POST",
    headers: { "PAYMENT-SIGNATURE": payment.body.paymentHeader },
    body: JSON.stringify(requestBody)
  });

  renderResult(paid.body);
});

init();
