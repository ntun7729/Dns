const fields = Object.fromEntries(
  [
    "overallStatus", "lastUpdated", "certificateBanner", "certificateBannerTitle",
    "certificateBannerText", "httpStatus", "dotStatus", "frpcStatus",
    "certificateStatus", "queryCount", "blockedCount", "errorCount",
    "upstreamLatency", "activeConnections", "activeProfileMetric", "apiDetail",
    "certificateDetail", "dotDetail", "upstreamDetail", "filterDetail", "frpcDetail",
    "publicHostname", "publicDot", "localDot", "frpsControl", "authMode",
    "frpcSession", "certificateExpiry", "activeProfile", "filterPresetStatus",
    "loadedBlockDomains", "upstreamStrategy", "upstreamDns", "lastUpstreamUsed",
    "upstreamFailovers", "historyWindow", "runtimeLogging", "lastQuery",
    "serviceError", "refreshButton", "apiDot", "certificateDot", "dotDot",
    "upstreamDot", "filterDot", "frpcDot", "diagnosticsList", "timeoutErrors",
    "socketErrors", "malformedErrors", "internalErrors", "clientDisconnects",
    "peakConnections", "resolverGrid", "upstreamPoolStatus", "trafficChart",
    "latencyChart", "trafficChartRange", "controlsPanel", "profileSelect",
    "activateProfileButton", "newProfileButton", "duplicateProfileButton",
    "deleteProfileButton", "profileForm", "profileId", "profileName",
    "profileUpstreams", "profileStrategy", "profileFilterPreset",
    "profileFilterEnabled", "profileBlocklist", "profileAllowlist",
    "saveProfileButton", "refreshBlocklistButton", "exportProfilesButton",
    "importProfilesInput", "controlMessage",
  ].map((id) => [id, document.querySelector(`#${id}`)])
);

let controlState = null;
let latestStatus = null;

function formatUptime(seconds) {
  if (seconds === null || seconds === undefined) return "Unavailable";
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
  return `${seconds}s`;
}

function formatDate(value) {
  if (!value) return "Unavailable";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

function formatLatency(value) {
  return value === null || value === undefined ? "No samples" : `${Number(value).toFixed(1)} ms`;
}

function titleCase(value) {
  return String(value || "unknown")
    .split("-")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function setDot(element, state) {
  element.className = `dot ${state}`;
}

function setOverall(state) {
  const labels = { ok: "Operational", warn: "Warning", bad: "Needs attention" };
  fields.overallStatus.className = `status-pill ${state}`;
  fields.overallStatus.textContent = labels[state];
}

function certificateCopy(certificate, hostname) {
  if (certificate.valid) {
    const remaining = certificate.days_remaining === null ? "" : ` (${certificate.days_remaining} days remaining)`;
    return `Valid for ${hostname}; source: ${certificate.source}${remaining}.`;
  }
  return certificate.error || "Certificate is missing or invalid.";
}

function showCertificateWarning(certificate) {
  const warning = certificate.warning;
  if (!warning || warning.level === "green") {
    fields.certificateBanner.hidden = true;
    return;
  }
  const state = warning.level === "yellow" ? "warn" : "bad";
  fields.certificateBanner.className = `alert ${state}`;
  fields.certificateBannerTitle.textContent = warning.level === "critical" ? "Certificate failure" : "Certificate renewal notice";
  fields.certificateBannerText.textContent = warning.message;
  fields.certificateBanner.hidden = false;
}

function frpcCopy(data) {
  const state = data.checks.frpc;
  const auth = data.checks.frp_auth_mode;
  if (state === "disabled") return "FRPC is disabled.";
  if (state === "needs-config") return "Set FRP_SERVER_ADDR on Render.";
  if (state === "blocked") return "FRPC is blocked until the DoT listener becomes ready.";
  if (state === "running") {
    const session = data.frpc.session_seconds === null ? "" : ` Session: ${formatUptime(data.frpc.session_seconds)}.`;
    return `FRPC is running with ${auth} authentication.${session}`;
  }
  if (state === "starting") return `FRPC is starting with ${auth} authentication.`;
  if (state === "startup-failed") return data.frpc.last_error || "FRPC failed during startup.";
  if (state === "exited") return data.frpc.last_error || "FRPC exited unexpectedly.";
  return "FRPC has not started.";
}

function renderDiagnostics(items) {
  fields.diagnosticsList.replaceChildren();
  for (const item of items || []) {
    const row = document.createElement("div");
    row.className = `diagnostic ${item.severity || "info"}`;
    const marker = document.createElement("span");
    marker.className = "diagnostic-marker";
    const message = document.createElement("p");
    message.textContent = item.message;
    row.append(marker, message);
    fields.diagnosticsList.append(row);
  }
}

function renderResolvers(items, overallState) {
  fields.resolverGrid.replaceChildren();
  for (const resolver of items || []) {
    const card = document.createElement("article");
    card.className = `resolver-card ${resolver.state || "unknown"}`;
    const head = document.createElement("div");
    head.className = "resolver-head";
    const endpoint = document.createElement("strong");
    endpoint.textContent = resolver.endpoint;
    const state = document.createElement("span");
    state.className = `resolver-state ${resolver.state || "unknown"}`;
    state.textContent = titleCase(resolver.state);
    head.append(endpoint, state);
    const stats = document.createElement("dl");
    stats.className = "resolver-stats";
    const rows = [
      ["Latest", formatLatency(resolver.last_latency_ms)],
      ["Average", formatLatency(resolver.average_latency_ms)],
      ["Successes", resolver.successes],
      ["Failures", resolver.failures],
      ["Timeouts", resolver.timeouts],
      ["Last success", resolver.last_success_at ? formatDate(resolver.last_success_at) : "No success yet"],
    ];
    for (const [label, value] of rows) {
      const row = document.createElement("div");
      const term = document.createElement("dt");
      term.textContent = label;
      const detail = document.createElement("dd");
      detail.textContent = String(value);
      row.append(term, detail);
      stats.append(row);
    }
    card.append(head, stats);
    fields.resolverGrid.append(card);
  }
  const state = overallState || "unknown";
  fields.upstreamPoolStatus.className = `mini-pill ${state}`;
  fields.upstreamPoolStatus.textContent = titleCase(state);
}

function chartPalette() {
  const styles = getComputedStyle(document.documentElement);
  return {
    query: styles.getPropertyValue("--blue").trim() || "#60a5fa",
    blocked: styles.getPropertyValue("--amber").trim() || "#fbbf24",
    error: styles.getPropertyValue("--red").trim() || "#fb7185",
    latency: styles.getPropertyValue("--green").trim() || "#4ade80",
    grid: "rgba(255,255,255,0.09)",
    text: styles.getPropertyValue("--muted").trim() || "#a8b0c2",
  };
}

function drawChart(canvas, points, series, unit = "") {
  if (!canvas) return;
  const ratio = window.devicePixelRatio || 1;
  const width = Math.max(280, canvas.clientWidth || 600);
  const height = Number(canvas.getAttribute("height")) || 210;
  canvas.width = Math.floor(width * ratio);
  canvas.height = Math.floor(height * ratio);
  const ctx = canvas.getContext("2d");
  ctx.scale(ratio, ratio);
  ctx.clearRect(0, 0, width, height);

  const padding = { left: 42, right: 12, top: 12, bottom: 28 };
  const plotWidth = width - padding.left - padding.right;
  const plotHeight = height - padding.top - padding.bottom;
  const values = [];
  for (const point of points) {
    for (const item of series) {
      const value = Number(point[item.key]);
      if (Number.isFinite(value)) values.push(value);
    }
  }
  const maxValue = Math.max(1, ...values);
  const palette = chartPalette();

  ctx.lineWidth = 1;
  ctx.font = "11px system-ui";
  ctx.fillStyle = palette.text;
  ctx.strokeStyle = palette.grid;
  for (let i = 0; i <= 4; i += 1) {
    const y = padding.top + (plotHeight * i) / 4;
    ctx.beginPath();
    ctx.moveTo(padding.left, y);
    ctx.lineTo(width - padding.right, y);
    ctx.stroke();
    const label = `${Math.round(maxValue * (1 - i / 4))}${unit}`;
    ctx.fillText(label, 4, y + 4);
  }

  const count = Math.max(points.length, 2);
  for (const item of series) {
    ctx.strokeStyle = item.color;
    ctx.lineWidth = 2;
    ctx.beginPath();
    let started = false;
    points.forEach((point, index) => {
      const value = Number(point[item.key]);
      if (!Number.isFinite(value)) return;
      const x = padding.left + (index / (count - 1)) * plotWidth;
      const y = padding.top + plotHeight - (value / maxValue) * plotHeight;
      if (!started) {
        ctx.moveTo(x, y);
        started = true;
      } else {
        ctx.lineTo(x, y);
      }
    });
    ctx.stroke();
  }

  if (points.length) {
    ctx.fillStyle = palette.text;
    const first = new Date(points[0].time);
    const last = new Date(points[points.length - 1].time);
    ctx.fillText(first.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }), padding.left, height - 7);
    const lastLabel = last.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    ctx.fillText(lastLabel, width - padding.right - ctx.measureText(lastLabel).width, height - 7);
  }
}

function renderHistory(points) {
  const palette = chartPalette();
  drawChart(fields.trafficChart, points, [
    { key: "queries", color: palette.query },
    { key: "blocked", color: palette.blocked },
    { key: "errors", color: palette.error },
  ]);
  drawChart(fields.latencyChart, points, [{ key: "latency_ms", color: palette.latency }], "");
}

function profileById(id) {
  return controlState?.profiles?.find((profile) => profile.id === id) || null;
}

function populateProfileForm(profile) {
  if (!profile) return;
  fields.profileId.value = profile.id || "";
  fields.profileName.value = profile.name || "";
  fields.profileUpstreams.value = profile.upstream_servers || "";
  fields.profileStrategy.value = profile.upstream_strategy || "primary_failover";
  fields.profileFilterEnabled.checked = Boolean(profile.filter_enabled);
  fields.profileFilterPreset.value = profile.filter_preset || "off";
  fields.profileBlocklist.value = profile.manual_block_domains || "";
  fields.profileAllowlist.value = profile.allow_domains || "";
}

function renderControl(control) {
  controlState = control;
  fields.controlsPanel.hidden = false;
  fields.profileSelect.replaceChildren();
  for (const profile of control.profiles || []) {
    const option = document.createElement("option");
    option.value = profile.id;
    option.textContent = profile.id === control.active_profile_id ? `${profile.name} (active)` : profile.name;
    fields.profileSelect.append(option);
  }
  fields.profileFilterPreset.replaceChildren();
  for (const preset of control.filter_presets || []) {
    const option = document.createElement("option");
    option.value = preset.id;
    option.textContent = preset.name;
    fields.profileFilterPreset.append(option);
  }
  fields.profileSelect.value = control.active_profile_id;
  populateProfileForm(profileById(control.active_profile_id));
}

async function loadControl() {
  try {
    const response = await fetch("/api/control", { cache: "no-store" });
    if (response.status === 403) {
      fields.controlsPanel.hidden = true;
      return;
    }
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    renderControl(data.control);
  } catch (error) {
    fields.controlMessage.textContent = `Controls unavailable: ${error.message}`;
    fields.controlMessage.className = "control-message error";
  }
}

function profileFormPayload() {
  return {
    action: "save_profile",
    id: fields.profileId.value,
    name: fields.profileName.value,
    upstream_servers: fields.profileUpstreams.value,
    upstream_strategy: fields.profileStrategy.value,
    filter_enabled: fields.profileFilterEnabled.checked,
    filter_preset: fields.profileFilterPreset.value,
    manual_block_domains: fields.profileBlocklist.value,
    allow_domains: fields.profileAllowlist.value,
    activate: true,
  };
}

async function postControl(payload, successMessage) {
  fields.controlMessage.textContent = "Saving...";
  fields.controlMessage.className = "control-message";
  const response = await fetch("/api/control", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.ok) throw new Error(data.error || `HTTP ${response.status}`);
  renderControl(data.control);
  fields.controlMessage.textContent = successMessage;
  fields.controlMessage.className = "control-message success";
  await refreshStatus();
}

async function refreshStatus() {
  fields.refreshButton.disabled = true;
  try {
    const response = await fetch("/api/status", { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    latestStatus = data;
    const certificate = data.certificate;
    const metrics = data.metrics;
    const endpoints = data.endpoints;
    const errorTypes = metrics.dns_error_types || {};
    const upstreams = metrics.upstreams || [];
    const filtering = data.filtering || {};
    const profile = data.profile || {};

    fields.httpStatus.textContent = titleCase(data.checks.http);
    fields.dotStatus.textContent = titleCase(data.checks.dot_listener);
    fields.frpcStatus.textContent = titleCase(data.checks.frpc);
    fields.certificateStatus.textContent = certificate.valid ? "Valid" : "Invalid";
    fields.queryCount.textContent = metrics.dns_queries;
    fields.blockedCount.textContent = metrics.dns_blocked || 0;
    fields.errorCount.textContent = metrics.dns_errors;
    fields.upstreamLatency.textContent = formatLatency(metrics.upstream_last_latency_ms);
    fields.activeConnections.textContent = metrics.active_connections ?? 0;
    fields.activeProfileMetric.textContent = profile.name || "Default";
    fields.apiDetail.textContent = `Healthy for ${formatUptime(data.uptime_seconds)} on ${endpoints.http}.`;
    fields.certificateDetail.textContent = certificateCopy(certificate, data.public_dns_hostname || "the configured hostname");
    fields.dotDetail.textContent = `Listener: ${endpoints.dot_local}; upstream pool: ${upstreams.length} resolvers.`;
    fields.upstreamDetail.textContent = metrics.upstream_last_latency_ms === null
      ? `No successful resolver samples yet. Strategy: ${titleCase(data.configuration.upstream_strategy)}.`
      : `Latest ${formatLatency(metrics.upstream_last_latency_ms)} via ${metrics.upstream_last_used}; average ${formatLatency(metrics.upstream_average_latency_ms)}; ${metrics.upstream_failovers} failovers.`;
    fields.filterDetail.textContent = filtering.enabled
      ? `${filtering.preset_name || titleCase(filtering.preset)} active with ${filtering.downloaded_domains || 0} downloaded domains and ${filtering.blocked_queries || 0} blocked queries.`
      : "Filtering is disabled for the active profile.";
    fields.frpcDetail.textContent = frpcCopy(data);
    fields.publicHostname.textContent = data.public_dns_hostname || "Not configured";
    fields.publicDot.textContent = endpoints.dot_public || "Not configured";
    fields.localDot.textContent = endpoints.dot_local;
    fields.frpsControl.textContent = endpoints.frps_control || "Not configured";
    fields.authMode.textContent = titleCase(data.checks.frp_auth_mode);
    fields.frpcSession.textContent = data.frpc.session_seconds === null ? "Not running" : formatUptime(data.frpc.session_seconds);
    fields.certificateExpiry.textContent = formatDate(certificate.expires_at);
    fields.activeProfile.textContent = `${profile.name || "Default"} (${profile.profile_count || 1})`;
    fields.filterPresetStatus.textContent = filtering.enabled ? (filtering.preset_name || titleCase(filtering.preset)) : "Off";
    fields.loadedBlockDomains.textContent = filtering.downloaded_domains || 0;
    fields.upstreamStrategy.textContent = titleCase(data.configuration.upstream_strategy || "unknown");
    fields.upstreamDns.textContent = (data.configuration.upstream_servers || []).join(", ") || "Not configured";
    fields.lastUpstreamUsed.textContent = metrics.upstream_last_used || "No successful query yet";
    fields.upstreamFailovers.textContent = metrics.upstream_failovers || 0;
    fields.historyWindow.textContent = `${data.configuration.history_minutes || 0} minutes`;
    fields.runtimeLogging.textContent = titleCase(data.configuration.runtime_logging || "unknown");
    fields.lastQuery.textContent = metrics.last_query_at ? formatDate(metrics.last_query_at) : "No queries yet";
    fields.serviceError.textContent = certificate.error || data.frpc.last_error || filtering.last_error || "";
    fields.timeoutErrors.textContent = errorTypes.upstream_timeout || 0;
    fields.socketErrors.textContent = errorTypes.upstream_socket || 0;
    fields.malformedErrors.textContent = errorTypes.malformed_message || 0;
    fields.internalErrors.textContent = errorTypes.internal_error || 0;
    fields.clientDisconnects.textContent = metrics.client_disconnects || 0;
    fields.peakConnections.textContent = metrics.peak_connections || 0;
    fields.lastUpdated.textContent = `Updated ${new Date().toLocaleTimeString()}`;
    fields.trafficChartRange.textContent = `${data.configuration.history_minutes || 0} min`;

    showCertificateWarning(certificate);
    renderDiagnostics(data.diagnostics);
    renderResolvers(upstreams, data.checks.upstream);
    renderHistory(data.history || []);

    setDot(fields.apiDot, "ok");
    setDot(fields.certificateDot, certificate.valid ? (certificate.warning?.renewal_recommended ? "warn" : "ok") : "bad");
    setDot(fields.dotDot, ["running", "disabled"].includes(data.checks.dot_listener) ? "ok" : "bad");
    setDot(fields.upstreamDot, data.checks.upstream === "healthy" ? "ok" : data.checks.upstream === "unknown" ? "warn" : "bad");
    setDot(fields.filterDot, filtering.last_error ? "warn" : filtering.enabled ? "ok" : "neutral");
    setDot(fields.frpcDot, ["running", "disabled"].includes(data.checks.frpc) ? "ok" : ["starting", "not-started"].includes(data.checks.frpc) ? "warn" : "bad");

    const warning = certificate.warning?.renewal_recommended || (data.diagnostics || []).some((item) => item.severity === "warning");
    const critical = !data.ready || (data.diagnostics || []).some((item) => item.severity === "critical");
    setOverall(critical ? "bad" : warning ? "warn" : "ok");

    if (data.access_control?.controls_available && fields.controlsPanel.hidden) await loadControl();
  } catch (error) {
    fields.overallStatus.className = "status-pill bad";
    fields.overallStatus.textContent = "Offline";
    fields.apiDetail.textContent = `Status API unavailable: ${error.message}`;
    fields.lastUpdated.textContent = "Update failed";
    setDot(fields.apiDot, "bad");
  } finally {
    fields.refreshButton.disabled = false;
  }
}

fields.refreshButton.addEventListener("click", refreshStatus);
fields.profileSelect.addEventListener("change", () => populateProfileForm(profileById(fields.profileSelect.value)));
fields.profileForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  try {
    await postControl(profileFormPayload(), "Profile saved and activated.");
  } catch (error) {
    fields.controlMessage.textContent = error.message;
    fields.controlMessage.className = "control-message error";
  }
});
fields.newProfileButton.addEventListener("click", () => {
  fields.profileId.value = "";
  fields.profileName.value = "New Profile";
  fields.profileUpstreams.value = latestStatus?.configuration?.upstream_servers?.join(",") || "1.1.1.1:53";
  fields.profileStrategy.value = latestStatus?.configuration?.upstream_strategy || "primary_failover";
  fields.profileFilterEnabled.checked = false;
  fields.profileFilterPreset.value = "off";
  fields.profileBlocklist.value = "";
  fields.profileAllowlist.value = "";
  fields.controlMessage.textContent = "Editing a new profile.";
  fields.controlMessage.className = "control-message";
});
fields.activateProfileButton.addEventListener("click", async () => {
  try {
    await postControl({ action: "activate_profile", id: fields.profileSelect.value }, "Profile activated.");
  } catch (error) {
    fields.controlMessage.textContent = error.message;
    fields.controlMessage.className = "control-message error";
  }
});
fields.duplicateProfileButton.addEventListener("click", async () => {
  try {
    await postControl({ action: "duplicate_profile", id: fields.profileSelect.value }, "Profile duplicated and activated.");
  } catch (error) {
    fields.controlMessage.textContent = error.message;
    fields.controlMessage.className = "control-message error";
  }
});
fields.deleteProfileButton.addEventListener("click", async () => {
  if (!window.confirm("Delete this profile?")) return;
  try {
    await postControl({ action: "delete_profile", id: fields.profileSelect.value }, "Profile deleted.");
  } catch (error) {
    fields.controlMessage.textContent = error.message;
    fields.controlMessage.className = "control-message error";
  }
});
fields.refreshBlocklistButton.addEventListener("click", async () => {
  try {
    await postControl({ action: "refresh_blocklist" }, "Blocklist refresh started.");
  } catch (error) {
    fields.controlMessage.textContent = error.message;
    fields.controlMessage.className = "control-message error";
  }
});
fields.exportProfilesButton.addEventListener("click", async () => {
  try {
    const response = await fetch("/api/control/export", { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const payload = await response.json();
    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `dns-dashboard-profiles-${new Date().toISOString().slice(0, 10)}.json`;
    link.click();
    URL.revokeObjectURL(link.href);
    fields.controlMessage.textContent = "Profile backup exported.";
    fields.controlMessage.className = "control-message success";
  } catch (error) {
    fields.controlMessage.textContent = error.message;
    fields.controlMessage.className = "control-message error";
  }
});
fields.importProfilesInput.addEventListener("change", async () => {
  const file = fields.importProfilesInput.files?.[0];
  if (!file) return;
  try {
    const exported = JSON.parse(await file.text());
    await postControl({ action: "import_profiles", export: exported }, "Profiles imported.");
  } catch (error) {
    fields.controlMessage.textContent = `Import failed: ${error.message}`;
    fields.controlMessage.className = "control-message error";
  } finally {
    fields.importProfilesInput.value = "";
  }
});

window.addEventListener("resize", () => {
  if (latestStatus) renderHistory(latestStatus.history || []);
});

refreshStatus();
setInterval(refreshStatus, 15000);
