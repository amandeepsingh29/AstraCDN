const state = {
  health: {},
  analytics: null,
  origins: [],
  routes: [],
  domains: [],
  audits: [],
  routeRuleVersions: [],
  apiKeys: [],
  tenants: [],
  tenantUsers: [],
  billingAccounts: [],
  billingWebhookEvents: [],
  edges: [],
  assets: [],
  assetStorage: null,
  token: localStorage.getItem("astracdn.dashboard.token") || ""
};

const $ = (id) => document.getElementById(id);

async function api(path, options = {}) {
  const headers = {
    ...authHeaders(),
    ...(options.headers || {})
  };
  if (!(options.body instanceof FormData)) {
    headers["Content-Type"] = "application/json";
  }
  const response = await fetch(path, {
    ...options,
    headers
  });
  const text = await response.text();
  let body = text;
  try {
    body = text ? JSON.parse(text) : {};
  } catch {
    body = text;
  }
  if (!response.ok) {
    throw new Error(typeof body === "string" ? body : JSON.stringify(body));
  }
  return body;
}

function authHeaders() {
  if (!state.token) return {};
  return {
    "X-AstraCDN-Dashboard-Token": state.token
  };
}

async function safe(name, fn) {
  try {
    return { name, ok: true, value: await fn() };
  } catch (error) {
    return { name, ok: false, error: error.message };
  }
}

async function refresh() {
  renderAuth();
  const results = await Promise.all([
    safe("edge", () => api("/api/edge/health")),
    safe("control", () => api("/api/control/health")),
    safe("inference", () => api("/api/inference/health")),
    safe("analytics", () => api("/api/edge/v1/cache/analytics")),
    safe("origins", () => api("/api/control/v1/origins")),
    safe("routes", () => api("/api/control/v1/routes")),
    safe("domains", () => api("/api/control/v1/domains")),
    safe("audits", () => api("/api/control/v1/audit-logs?limit=8")),
    safe("routeRuleVersions", () => api(routeRuleVersionsPath())),
    safe("apiKeys", () => api("/api/control/v1/api-keys")),
    safe("tenants", () => api("/api/control/v1/tenants")),
    safe("tenantUsers", () => api("/api/control/v1/rbac/users")),
    safe("billingAccounts", () => api("/api/control/v1/billing/accounts")),
    safe("billingWebhookEvents", () => api("/api/control/v1/billing/webhook-events?limit=8")),
    safe("edgeHealth", () => api("/api/control/v1/edge/health")),
    safe("assetStorage", () => api("/api/assets/storage")),
    safe("assets", () => api(assetListPath()))
  ]);

  for (const result of results) {
    if (result.name === "edge" || result.name === "control" || result.name === "inference") {
      state.health[result.name] = result;
    }
    if (result.ok && result.name === "analytics") state.analytics = result.value.cache || result.value;
    if (result.ok && result.name === "origins") state.origins = result.value.origins || [];
    if (result.ok && result.name === "routes") state.routes = result.value.routes || [];
    if (result.ok && result.name === "domains") state.domains = result.value.domains || [];
    if (result.ok && result.name === "audits") state.audits = result.value.audit_logs || [];
    if (result.ok && result.name === "routeRuleVersions") state.routeRuleVersions = result.value.route_rule_versions || [];
    if (result.ok && result.name === "apiKeys") state.apiKeys = result.value.api_keys || [];
    if (result.ok && result.name === "tenants") state.tenants = result.value.tenants || [];
    if (result.ok && result.name === "tenantUsers") state.tenantUsers = result.value.users || [];
    if (result.ok && result.name === "billingAccounts") state.billingAccounts = result.value.billing_accounts || [];
    if (result.ok && result.name === "billingWebhookEvents") state.billingWebhookEvents = result.value.billing_webhook_events || [];
    if (result.ok && result.name === "edgeHealth") state.edges = result.value.edges || [];
    if (result.ok && result.name === "assetStorage") state.assetStorage = result.value;
    if (result.ok && result.name === "assets") state.assets = result.value.assets || [];
  }

  render();
}

function render() {
  renderAuth();
  const healthValues = Object.values(state.health);
  const allHealthy = healthValues.length > 0 && healthValues.every((item) => item.ok);
  $("system-status").textContent = allHealthy ? "All local services healthy" : "Some services need attention";
  $("system-subtitle").textContent = allHealthy ? "Edge, control, and inference are responding." : "Check the health cards below.";

  const analytics = state.analytics || {};
  $("metric-requests").textContent = number(analytics.requests || 0);
  $("metric-hit-ratio").textContent = percent(analytics.hit_ratio || 0);
  $("metric-routes").textContent = number(state.routes.length);
  $("metric-domains").textContent = number(state.domains.length);

  renderHealth();
  renderRoutes();
  renderOrigins();
  renderDomains();
  renderAuditLogs();
  renderRouteRuleVersions();
  renderAPIKeys();
  renderTenants();
  renderTenantUsers();
  renderBillingAccounts();
  renderBillingWebhookEvents();
  renderCacheLayers();
  renderEdgeHealth();
  renderAssetStorage();
  renderAssets();
}

function renderAuth() {
  $("auth-status").textContent = state.token ? "Dashboard API unlocked" : "Dashboard token required";
  $("dashboard-token").value = state.token;
}

function renderHealth() {
  $("health-list").innerHTML = ["edge", "control", "inference"].map((name) => {
    const item = state.health[name];
    const ok = item && item.ok;
    return `
      <div class="status-item">
        <div>
          <strong>${escapeHTML(name)}</strong>
          <div>${ok ? "Responding" : escapeHTML(item?.error || "Not checked")}</div>
        </div>
        <span class="${ok ? "status-ok" : "status-bad"}">${ok ? "OK" : "FAIL"}</span>
      </div>
    `;
  }).join("");
}

function renderRoutes() {
  const rows = state.routes.map((route) => [
    route.id,
    route.host,
    route.path_prefix,
    route.origin_name || route.origin_id,
    route.cache_policy?.mode || route.cache_mode || "origin",
    route.cache_policy?.ttl_seconds ?? route.cache_ttl_seconds ?? ""
  ]);
  $("routes").innerHTML = table(["ID", "Host", "Path", "Origin", "Cache", "TTL"], rows);
}

function renderOrigins() {
  $("origins").innerHTML = state.origins.length ? state.origins.map((origin) => `
    <div class="mini-card">
      <strong>${escapeHTML(origin.name)}</strong>
      <div>${escapeHTML(origin.base_url)}</div>
      <small>ID ${escapeHTML(origin.id)} | ${escapeHTML(origin.status || "active")}</small>
    </div>
  `).join("") : empty("No origins configured.");
}

function renderDomains() {
  $("domains").innerHTML = state.domains.length ? state.domains.map((domain) => `
    <div class="mini-card">
      <strong>${escapeHTML(domain.host)}</strong>
      <div class="${domain.status === "active" || domain.status === "verified" ? "status-ok" : "status-bad"}">${escapeHTML(domain.status || "unknown")}</div>
      <small>TLS ${escapeHTML(domain.tls_mode || "managed")} | route ${escapeHTML(domain.route_id || "-")}</small>
      <div class="domain-record">
        <span>TXT name</span>
        <code>${escapeHTML(domain.dns_txt_name || "-")}</code>
        <span>TXT value</span>
        <code>${escapeHTML(domain.dns_txt_value || "-")}</code>
      </div>
      <div class="actions-cell">
        <button type="button" class="ghost tiny verify-domain" data-host="${escapeHTML(domain.host)}">Verify</button>
        <button type="button" class="ghost tiny copy-domain-txt" data-value="${escapeHTML(domain.dns_txt_value || "")}">Copy TXT</button>
      </div>
    </div>
  `).join("") : empty("No domains configured.");
}

function renderAuditLogs() {
  const rows = state.audits.map((entry) => [
    entry.created_at || "",
    entry.actor || "",
    entry.action || "",
    entry.resource_type || "",
    entry.resource_id || ""
  ]);
  $("audit-logs").innerHTML = table(["Time", "Actor", "Action", "Resource", "ID"], rows);
}

function renderRouteRuleVersions() {
  const rows = state.routeRuleVersions.map((version) => [
    version.created_at || "",
    version.route_id || "",
    version.version || "",
    version.changed_by || "",
    routeRuleSummary(version)
  ]);
  $("route-rule-versions").innerHTML = table(["Time", "Route", "Version", "Changed by", "Rules"], rows);
}

function renderAPIKeys() {
  $("api-keys").innerHTML = state.apiKeys.length ? `
    <table>
      <thead><tr><th>ID</th><th>Name</th><th>Scopes</th><th>Status</th><th>Created</th><th>Actions</th></tr></thead>
      <tbody>
        ${state.apiKeys.map((key) => `
          <tr>
            <td>${escapeHTML(key.id)}</td>
            <td>${escapeHTML(key.name)}</td>
            <td>${escapeHTML((key.scopes || []).join(", "))}</td>
            <td>${escapeHTML(key.revoked_at ? "revoked" : "active")}</td>
            <td>${escapeHTML(key.created_at || "")}</td>
            <td class="actions-cell">
              <button type="button" class="danger tiny revoke-api-key" data-id="${escapeHTML(key.id)}" ${key.revoked_at ? "disabled" : ""}>Revoke</button>
            </td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  ` : empty("No persisted API keys yet.");
}

function renderTenants() {
  const rows = state.tenants.map((tenant) => [
    tenant.id,
    tenant.name,
    tenant.slug,
    tenant.status || ""
  ]);
  $("tenants").innerHTML = table(["ID", "Name", "Slug", "Status"], rows);
}

function renderTenantUsers() {
  const rows = state.tenantUsers.map((user) => [
    user.id,
    user.tenant_id,
    user.email,
    user.role,
    user.status || ""
  ]);
  $("tenant-users").innerHTML = table(["ID", "Tenant", "Email", "Role", "Status"], rows);
}

function renderBillingAccounts() {
  const rows = state.billingAccounts.map((account) => [
    account.id,
    account.tenant_id,
    account.provider,
    account.plan,
    account.status || "",
    account.provider_customer_id || ""
  ]);
  $("billing-accounts").innerHTML = table(["ID", "Tenant", "Provider", "Plan", "Status", "Customer"], rows);
}

function renderBillingWebhookEvents() {
  const rows = state.billingWebhookEvents.map((event) => [
    event.processed_at || event.created_at || "",
    event.provider || "",
    event.event_id || "",
    event.billing_account_id || "",
    event.status || ""
  ]);
  $("billing-webhook-events").innerHTML = table(["Time", "Provider", "Event", "Account", "Status"], rows);
}

function renderCacheLayers() {
  const byLayer = state.analytics?.by_layer || {};
  const entries = Object.entries(byLayer);
  $("cache-layers").innerHTML = entries.length ? entries.map(([layer, metric]) => `
    <div class="mini-card">
      <strong>${escapeHTML(layer)}</strong>
      <div>${number(metric.requests || 0)} requests</div>
      <small>${escapeHTML(metric.result || "")}</small>
    </div>
  `).join("") : empty("No edge cache traffic yet.");
}

function renderEdgeHealth() {
  $("edge-health").innerHTML = state.edges.length ? state.edges.map((edge) => `
    <div class="mini-card">
      <strong>${escapeHTML(edge.node_id)}</strong>
      <div class="${edge.healthy ? "status-ok" : "status-bad"}">${edge.healthy ? "healthy" : "stale"}</div>
      <small>${escapeHTML(edge.address || "")}</small>
    </div>
  `).join("") : empty("No edge heartbeat recorded yet.");
}

function renderAssets() {
  const folder = $("asset-filter-form")?.elements.folder?.value?.trim() || "";
  $("assets").innerHTML = state.assets.length ? `
    <table>
      <thead><tr><th>Name</th><th>Folder</th><th>Size</th><th>Type</th><th>Public URL</th><th>Actions</th></tr></thead>
      <tbody>
        ${state.assets.map((asset) => `
          <tr>
            <td>${escapeHTML(asset.name)}</td>
            <td>${escapeHTML(asset.folder || ".")}</td>
            <td>${escapeHTML(formatBytes(asset.bytes || 0))}</td>
            <td>${escapeHTML(asset.content_type || "-")}</td>
            <td><code>${escapeHTML(asset.public_url || asset.edge_path)}</code></td>
            <td class="actions-cell">
              <button type="button" class="ghost tiny use-asset" data-edge-path="${escapeHTML(asset.edge_path)}">Test</button>
              <button type="button" class="ghost tiny prewarm-asset" data-edge-path="${escapeHTML(asset.edge_path)}">Prewarm</button>
              <button type="button" class="ghost tiny purge-asset" data-edge-path="${escapeHTML(asset.edge_path)}">Purge</button>
              <button type="button" class="ghost tiny copy-asset-url" data-public-url="${escapeHTML(asset.public_url || asset.edge_path)}">Copy URL</button>
              <button type="button" class="danger tiny delete-asset" data-edge-path="${escapeHTML(asset.edge_path)}">Delete</button>
            </td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  ` : empty(folder ? `No assets found under ${folder}.` : "No assets uploaded yet.");
}

function renderAssetStorage() {
  const storage = state.assetStorage || {};
  const mode = storage.mode || "unknown";
  const configured = storage.configured !== false;
  const location = mode === "s3"
    ? [storage.bucket, storage.prefix].filter(Boolean).join("/") || storage.endpoint || "S3 bucket"
    : storage.asset_dir || "local asset directory";
  $("asset-storage-mode").textContent = mode.toUpperCase();
  $("asset-storage-location").textContent = location;
  $("asset-storage-status").textContent = configured ? "configured" : "not configured";
  $("asset-storage-status").className = configured ? "status-ok" : "status-bad";
  $("asset-upload-hint").textContent = mode === "s3"
    ? "Uploads are written to S3-compatible object storage, then served through `/edge/assets/...`."
    : "Uploads are saved into the local origin asset directory, then served through `/edge/assets/...`.";
  $("asset-inventory-title").textContent = mode === "s3" ? "S3 asset inventory" : "Local asset inventory";
}

function renderCDNFetch(result) {
  $("cdn-fetch-summary").innerHTML = `
    <div class="fetch-pill"><span>Status</span><strong>${escapeHTML(result.status)}</strong></div>
    <div class="fetch-pill"><span>Cache</span><strong>${escapeHTML(result.cache || "-")}</strong></div>
    <div class="fetch-pill"><span>Layer</span><strong>${escapeHTML(result.cache_layer || "-")}</strong></div>
    <div class="fetch-pill"><span>Type</span><strong>${escapeHTML(result.content_type || "-")}</strong></div>
  `;
  $("cdn-fetch-result").textContent = JSON.stringify(result, null, 2);
}

function assetListPath() {
  const form = $("asset-filter-form");
  const folder = form?.elements.folder?.value?.trim() || "";
  const limitRaw = form?.elements.limit?.value || "20";
  const limit = Math.min(Math.max(Number(limitRaw) || 20, 1), 1000);
  const params = new URLSearchParams({ limit: String(limit) });
  if (folder) params.set("folder", folder);
  return `/api/assets?${params.toString()}`;
}

function assetActionHost() {
  return $("asset-action-host")?.value?.trim() || "cdn.localhost";
}

function routeRuleVersionsPath() {
  const form = $("route-rule-version-form");
  const routeID = Number(form?.elements.route_id?.value || 0);
  const limitRaw = form?.elements.limit?.value || "10";
  const limit = Math.min(Math.max(Number(limitRaw) || 10, 1), 100);
  const params = new URLSearchParams({ limit: String(limit) });
  if (routeID > 0) params.set("route_id", String(routeID));
  return `/api/control/v1/route-rule-versions?${params.toString()}`;
}

async function prewarmAssets(paths) {
  if (!paths.length) {
    $("asset-upload-result").textContent = "No loaded assets to prewarm.";
    return;
  }
  const result = await api("/api/control/v1/cache/prewarm", {
    method: "POST",
    body: JSON.stringify({
      host: assetActionHost(),
      paths,
      requested_by: "dashboard"
    })
  });
  $("asset-upload-result").textContent = JSON.stringify(result, null, 2);
  await refresh();
}

async function purgeAssets(paths) {
  if (!paths.length) {
    $("asset-upload-result").textContent = "No loaded assets to purge.";
    return;
  }
  const result = await api("/api/control/v1/cache/invalidate", {
    method: "POST",
    body: JSON.stringify({
      host: assetActionHost(),
      keys: paths,
      requested_by: "dashboard"
    })
  });
  $("asset-upload-result").textContent = JSON.stringify(result, null, 2);
  await refresh();
}

function table(headers, rows) {
  if (!rows.length) return empty("No records yet.");
  return `
    <table>
      <thead><tr>${headers.map((header) => `<th>${escapeHTML(header)}</th>`).join("")}</tr></thead>
      <tbody>
        ${rows.map((row) => `<tr>${row.map((cell) => `<td>${escapeHTML(cell ?? "")}</td>`).join("")}</tr>`).join("")}
      </tbody>
    </table>
  `;
}

function empty(message) {
  return `<div class="mini-card">${escapeHTML(message)}</div>`;
}

function valuesList(raw) {
  return raw.split(",").map((value) => value.trim()).filter(Boolean);
}

function number(value) {
  return new Intl.NumberFormat().format(value);
}

function percent(value) {
  return `${Math.round(value * 100)}%`;
}

function formatBytes(value) {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MiB`;
}

function routeRuleSummary(version) {
  const parts = [];
  const deliveryRules = version.delivery_rules || {};
  const wafRules = version.waf_rules || {};
  const rateLimitRules = version.rate_limit_rules || [];
  const headerCount = Array.isArray(deliveryRules.set_headers) ? deliveryRules.set_headers.length : 0;
  const redirectCount = Array.isArray(deliveryRules.redirects) ? deliveryRules.redirects.length : 0;
  if (headerCount) parts.push(`${headerCount} headers`);
  if (redirectCount) parts.push(`${redirectCount} redirects`);
  if (wafRules.enabled) parts.push("WAF enabled");
  if (Array.isArray(rateLimitRules) && rateLimitRules.length) parts.push(`${rateLimitRules.length} rate limits`);
  return parts.length ? parts.join(", ") : "No dynamic rules";
}

function escapeHTML(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

$("refresh").addEventListener("click", refresh);

$("auth-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const token = new FormData(event.currentTarget).get("token").trim();
  state.token = token;
  if (token) {
    localStorage.setItem("astracdn.dashboard.token", token);
  } else {
    localStorage.removeItem("astracdn.dashboard.token");
  }
  await refresh();
});

$("lock-dashboard").addEventListener("click", async () => {
  state.token = "";
  localStorage.removeItem("astracdn.dashboard.token");
  state.health = {};
  state.analytics = null;
  state.origins = [];
  state.routes = [];
  state.domains = [];
  state.audits = [];
  state.routeRuleVersions = [];
  state.apiKeys = [];
  state.tenants = [];
  state.tenantUsers = [];
  state.billingAccounts = [];
  state.billingWebhookEvents = [];
  state.edges = [];
  state.assets = [];
  state.assetStorage = null;
  render();
});

$("cdn-fetch-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const host = form.get("host").trim();
  const path = form.get("path").trim();
  try {
    const result = await api(`/api/cdn/fetch?host=${encodeURIComponent(host)}&path=${encodeURIComponent(path)}`);
    renderCDNFetch(result);
    await refresh();
  } catch (error) {
    $("cdn-fetch-summary").innerHTML = "";
    $("cdn-fetch-result").textContent = error.message;
  }
});

$("asset-upload-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const host = form.get("host").trim() || "cdn.localhost";
  try {
    const result = await api("/api/assets/upload", {
      method: "POST",
      body: form
    });
    $("asset-upload-result").textContent = JSON.stringify(result, null, 2);
    $("cdn-fetch-form").elements.host.value = host;
    $("cdn-fetch-form").elements.path.value = result.edge_path;
    $("asset-filter-form").elements.folder.value = form.get("folder").trim() || "uploads";
    await refresh();
  } catch (error) {
    $("asset-upload-result").textContent = error.message;
  }
});

$("asset-filter-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (event.submitter?.id === "prewarm-loaded-assets") {
    try {
      await prewarmAssets(state.assets.map((asset) => asset.edge_path).filter(Boolean));
    } catch (error) {
      $("asset-upload-result").textContent = error.message;
    }
    return;
  }
  if (event.submitter?.id === "purge-loaded-assets") {
    try {
      await purgeAssets(state.assets.map((asset) => asset.edge_path).filter(Boolean));
    } catch (error) {
      $("asset-upload-result").textContent = error.message;
    }
    return;
  }
  try {
    await refresh();
  } catch (error) {
    $("asset-upload-result").textContent = error.message;
  }
});

$("route-rule-version-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await refresh();
  } catch (error) {
    $("route-rule-versions").innerHTML = empty(error.message);
  }
});

$("api-key-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const payload = {
    name: form.get("name").trim(),
    scopes: valuesList(form.get("scopes"))
  };
  try {
    const result = await api("/api/control/v1/api-keys", {
      method: "POST",
      body: JSON.stringify(payload)
    });
    $("api-key-result").textContent = JSON.stringify(result, null, 2);
    await refresh();
  } catch (error) {
    $("api-key-result").textContent = error.message;
  }
});

$("api-keys").addEventListener("click", (event) => {
  const button = event.target.closest(".revoke-api-key");
  if (!button) return;
  const id = Number(button.dataset.id);
  if (!id || !confirm(`Revoke API key ${id}?`)) return;
  api("/api/control/v1/api-keys/revoke", {
    method: "POST",
    body: JSON.stringify({ id })
  }).then(async (result) => {
    $("api-key-result").textContent = JSON.stringify(result, null, 2);
    await refresh();
  }).catch((error) => {
    $("api-key-result").textContent = error.message;
  });
});

$("tenant-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const payload = {
    name: form.get("name").trim(),
    slug: form.get("slug").trim()
  };
  try {
    const result = await api("/api/control/v1/tenants", {
      method: "POST",
      body: JSON.stringify(payload)
    });
    $("tenant-result").textContent = JSON.stringify(result, null, 2);
    const tenantID = result.tenant?.id;
    if (tenantID) {
      $("tenant-user-form").elements.tenant_id.value = tenantID;
      $("billing-form").elements.tenant_id.value = tenantID;
    }
    await refresh();
  } catch (error) {
    $("tenant-result").textContent = error.message;
  }
});

$("tenant-user-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const payload = {
    tenant_id: Number(form.get("tenant_id")),
    email: form.get("email").trim(),
    role: form.get("role")
  };
  try {
    const result = await api("/api/control/v1/rbac/users", {
      method: "POST",
      body: JSON.stringify(payload)
    });
    $("tenant-user-result").textContent = JSON.stringify(result, null, 2);
    await refresh();
  } catch (error) {
    $("tenant-user-result").textContent = error.message;
  }
});

$("billing-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const payload = {
    tenant_id: Number(form.get("tenant_id")),
    provider: form.get("provider").trim(),
    provider_customer_id: form.get("provider_customer_id").trim(),
    plan: form.get("plan").trim(),
    status: "active"
  };
  try {
    const result = await api("/api/control/v1/billing/accounts", {
      method: "POST",
      body: JSON.stringify(payload)
    });
    $("billing-result").textContent = JSON.stringify(result, null, 2);
    await refresh();
  } catch (error) {
    $("billing-result").textContent = error.message;
  }
});

$("assets").addEventListener("click", (event) => {
  const useButton = event.target.closest(".use-asset");
  if (useButton) {
    $("cdn-fetch-form").elements.host.value = assetActionHost();
    $("cdn-fetch-form").elements.path.value = useButton.dataset.edgePath || "";
    $("cdn-fetch-result").textContent = `Ready to fetch ${useButton.dataset.edgePath || ""} on ${assetActionHost()}`;
    return;
  }

  const deleteButton = event.target.closest(".delete-asset");
  if (!deleteButton) {
    const prewarmButton = event.target.closest(".prewarm-asset");
    if (prewarmButton) {
      const edgePath = prewarmButton.dataset.edgePath || "";
      prewarmAssets(edgePath ? [edgePath] : []).catch((error) => {
        $("asset-upload-result").textContent = error.message;
      });
      return;
    }

    const purgeButton = event.target.closest(".purge-asset");
    if (purgeButton) {
      const edgePath = purgeButton.dataset.edgePath || "";
      purgeAssets(edgePath ? [edgePath] : []).catch((error) => {
        $("asset-upload-result").textContent = error.message;
      });
      return;
    }

    const copyButton = event.target.closest(".copy-asset-url");
    if (!copyButton) return;
    const value = copyButton.dataset.publicUrl || "";
    copyText(value).then(() => {
      $("asset-upload-result").textContent = `Copied ${value}`;
    }).catch(() => {
      $("asset-upload-result").textContent = value;
    });
    return;
  }
  const edgePath = deleteButton.dataset.edgePath || "";
  const host = assetActionHost();
  if (!edgePath || !confirm(`Delete ${edgePath} and purge CDN cache for ${host}?`)) return;
  api(`/api/assets?edge_path=${encodeURIComponent(edgePath)}&host=${encodeURIComponent(host)}`, {
    method: "DELETE"
  }).then(async (result) => {
    $("asset-upload-result").textContent = JSON.stringify(result, null, 2);
    await refresh();
  }).catch((error) => {
    $("asset-upload-result").textContent = error.message;
  });
});

async function copyText(value) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value);
    return;
  }
  const input = document.createElement("textarea");
  input.value = value;
  input.setAttribute("readonly", "readonly");
  input.style.position = "fixed";
  input.style.left = "-9999px";
  document.body.appendChild(input);
  input.select();
  document.execCommand("copy");
  input.remove();
}

$("purge-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const mode = form.get("mode");
  const payload = {
    requested_by: "dashboard"
  };
  const host = form.get("host").trim();
  if (host) payload.host = host;
  payload[mode] = valuesList(form.get("values"));
  try {
    const result = await api("/api/control/v1/cache/invalidate", {
      method: "POST",
      body: JSON.stringify(payload)
    });
    $("purge-result").textContent = JSON.stringify(result, null, 2);
    await refresh();
  } catch (error) {
    $("purge-result").textContent = error.message;
  }
});

$("origin-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const payload = {
    name: form.get("name").trim(),
    base_url: form.get("base_url").trim()
  };
  try {
    const result = await api("/api/control/v1/origins", {
      method: "POST",
      body: JSON.stringify(payload)
    });
    $("origin-result").textContent = JSON.stringify(result, null, 2);
    await refresh();
  } catch (error) {
    $("origin-result").textContent = error.message;
  }
});

$("route-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const headerPathPrefix = form.get("header_path_prefix").trim();
  const headerName = form.get("header_name").trim();
  const headerValue = form.get("header_value").trim();
  const wafPathPrefix = form.get("waf_path_prefix").trim();
  const rateLimitPathPrefix = form.get("rate_limit_path_prefix").trim();
  const rateLimitRPS = Number(form.get("rate_limit_rps"));
  const rateLimitBurst = Number(form.get("rate_limit_burst"));
  const payload = {
    host: form.get("host").trim(),
    path_prefix: form.get("path_prefix").trim(),
    origin_id: Number(form.get("origin_id")),
    cache_policy: {
      mode: "override",
      ttl_seconds: Number(form.get("ttl")),
      stale_while_revalidate_seconds: 60
    }
  };
  if (headerPathPrefix && headerName) {
    payload.delivery_rules = {
      set_headers: [{
        path_prefix: headerPathPrefix,
        name: headerName,
        value: headerValue
      }]
    };
  }
  if (form.get("waf_enabled") === "on" && wafPathPrefix) {
    payload.waf_rules = {
      enabled: true,
      path_prefixes: [wafPathPrefix]
    };
  }
  if (rateLimitPathPrefix && rateLimitRPS > 0 && rateLimitBurst > 0) {
    payload.rate_limit_rules = [{
      path_prefix: rateLimitPathPrefix,
      rps: rateLimitRPS,
      burst: rateLimitBurst
    }];
  }
  try {
    const result = await api("/api/control/v1/routes", {
      method: "POST",
      body: JSON.stringify(payload)
    });
    $("route-result").textContent = JSON.stringify(result, null, 2);
    await refresh();
  } catch (error) {
    $("route-result").textContent = error.message;
  }
});

$("domain-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const routeID = Number(form.get("route_id"));
  const payload = {
    host: form.get("host").trim(),
    tls_mode: form.get("tls_mode")
  };
  if (routeID > 0) payload.route_id = routeID;
  try {
    const result = await api("/api/control/v1/domains", {
      method: "POST",
      body: JSON.stringify(payload)
    });
    $("domain-result").textContent = JSON.stringify(result, null, 2);
    await refresh();
  } catch (error) {
    $("domain-result").textContent = error.message;
  }
});

$("domains").addEventListener("click", (event) => {
  const verifyButton = event.target.closest(".verify-domain");
  if (verifyButton) {
    const host = verifyButton.dataset.host || "";
    api("/api/control/v1/domains/verify", {
      method: "POST",
      body: JSON.stringify({ host })
    }).then(async (result) => {
      $("domain-result").textContent = JSON.stringify(result, null, 2);
      await refresh();
    }).catch((error) => {
      $("domain-result").textContent = error.message;
    });
    return;
  }

  const copyButton = event.target.closest(".copy-domain-txt");
  if (!copyButton) return;
  const value = copyButton.dataset.value || "";
  copyText(value).then(() => {
    $("domain-result").textContent = value ? `Copied TXT value ${value}` : "No TXT value available.";
  }).catch(() => {
    $("domain-result").textContent = value || "No TXT value available.";
  });
});

refresh();
setInterval(refresh, 15000);
