const fields = Object.fromEntries(
  [
    "overallStatus", "lastUpdated", "certificateBanner", "certificateBannerTitle",
    "certificateBannerText", "httpStatus", "dotStatus", "frpcStatus",
    "certificateStatus", "queryCount", "errorCount", "upstreamLatency",
    "activeConnections", "apiDetail", "certificateDetail", "dotDetail",
    "upstreamDetail", "frpcDetail", "publicHostname", "publicDot", "localDot",
    "frpsControl", "authMode", "frpcSession", "certificateExpiry",
    "tlsSecretFormat", "upstreamDns", "lastUpstreamSuccess", "lastQuery",
    "serviceError", "frpcLog", "refreshButton", "apiDot", "certificateDot",
    "dotDot", "upstreamDot", "frpcDot", "diagnosticsList", "timeoutErrors",
    "socketErrors", "malformedErrors", "internalErrors", "clientDisconnects",
    "peakConnections",
  ].map((id) => [id, document.querySelector(`#${id}`)])
);

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

async function refreshStatus() {
  fields.refreshButton.disabled = true;
  try {
    const response = await fetch("/api/status", { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    const certificate = data.certificate;
    const metrics = data.metrics;
    const endpoints = data.endpoints;
    const errorTypes = metrics.dns_error_types || {};

    fields.httpStatus.textContent = titleCase(data.checks.http);
    fields.dotStatus.textContent = titleCase(data.checks.dot_listener);
    fields.frpcStatus.textContent = titleCase(data.checks.frpc);
    fields.certificateStatus.textContent = certificate.valid ? "Valid" : "Invalid";
    fields.queryCount.textContent = metrics.dns_queries;
    fields.errorCount.textContent = metrics.dns_errors;
    fields.upstreamLatency.textContent = formatLatency(metrics.upstream_last_latency_ms);
    fields.activeConnections.textContent = metrics.active_connections ?? 0;
    fields.apiDetail.textContent = `Healthy for ${formatUptime(data.uptime_seconds)} on ${endpoints.http}.`;
    fields.certificateDetail.textContent = certificateCopy(certificate, data.public_dns_hostname || "the configured hostname");
    fields.dotDetail.textContent = `Listener: ${endpoints.dot_local}; upstream: ${endpoints.upstream_resolver}.`;
    fields.upstreamDetail.textContent = metrics.upstream_last_latency_ms === null
      ? `No successful resolver samples yet for ${endpoints.upstream_resolver}.`
      : `Latest ${formatLatency(metrics.upstream_last_latency_ms)}; average ${formatLatency(metrics.upstream_average_latency_ms)} across ${metrics.upstream_samples} samples.`;
    fields.frpcDetail.textContent = frpcCopy(data);
    fields.publicHostname.textContent = data.public_dns_hostname || "Not configured";
    fields.publicDot.textContent = endpoints.dot_public || "Not configured";
    fields.localDot.textContent = endpoints.dot_local;
    fields.frpsControl.textContent = endpoints.frps_control || "Not configured";
    fields.authMode.textContent = titleCase(data.checks.frp_auth_mode);
    fields.frpcSession.textContent = data.frpc.session_seconds === null ? "Not running" : formatUptime(data.frpc.session_seconds);
    fields.certificateExpiry.textContent = formatDate(certificate.expires_at);
    fields.tlsSecretFormat.textContent = titleCase(data.configuration.tls_secret_format || "unknown");
    fields.upstreamDns.textContent = endpoints.upstream_resolver;
    fields.lastUpstreamSuccess.textContent = metrics.upstream_last_success_at ? formatDate(metrics.upstream_last_success_at) : "No successful query yet";
    fields.lastQuery.textContent = metrics.last_query_at ? formatDate(metrics.last_query_at) : "No queries yet";
    fields.serviceError.textContent = certificate.error || data.frpc.last_error || "";
    fields.frpcLog.textContent = data.frpc.last_log ? `Last FRPC log: ${data.frpc.last_log}` : "";
    fields.timeoutErrors.textContent = errorTypes.upstream_timeout || 0;
    fields.socketErrors.textContent = errorTypes.upstream_socket || 0;
    fields.malformedErrors.textContent = errorTypes.malformed_message || 0;
    fields.internalErrors.textContent = errorTypes.internal_error || 0;
    fields.clientDisconnects.textContent = metrics.client_disconnects || 0;
    fields.peakConnections.textContent = metrics.peak_connections || 0;
    fields.lastUpdated.textContent = `Updated ${new Date().toLocaleTimeString()}`;

    showCertificateWarning(certificate);
    renderDiagnostics(data.diagnostics);

    setDot(fields.apiDot, "ok");
    setDot(fields.certificateDot, certificate.valid ? (certificate.warning?.renewal_recommended ? "warn" : "ok") : "bad");
    setDot(fields.dotDot, ["running", "disabled"].includes(data.checks.dot_listener) ? "ok" : "bad");
    setDot(fields.upstreamDot, metrics.upstream_last_failure_at && (!metrics.upstream_last_success_at || metrics.upstream_last_failure_at > metrics.upstream_last_success_at) ? "warn" : "ok");
    setDot(fields.frpcDot, ["running", "disabled"].includes(data.checks.frpc) ? "ok" : ["starting", "not-started"].includes(data.checks.frpc) ? "warn" : "bad");

    const warning = certificate.warning?.renewal_recommended || (data.diagnostics || []).some((item) => item.severity === "warning");
    const critical = !data.ready || (data.diagnostics || []).some((item) => item.severity === "critical");
    setOverall(critical ? "bad" : warning ? "warn" : "ok");
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
refreshStatus();
setInterval(refreshStatus, 10000);
