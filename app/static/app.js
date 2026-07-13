const fields = {
  overallStatus: document.querySelector("#overallStatus"),
  httpStatus: document.querySelector("#httpStatus"),
  dotStatus: document.querySelector("#dotStatus"),
  frpcStatus: document.querySelector("#frpcStatus"),
  certificateStatus: document.querySelector("#certificateStatus"),
  queryCount: document.querySelector("#queryCount"),
  errorCount: document.querySelector("#errorCount"),
  apiDetail: document.querySelector("#apiDetail"),
  certificateDetail: document.querySelector("#certificateDetail"),
  dotDetail: document.querySelector("#dotDetail"),
  frpcDetail: document.querySelector("#frpcDetail"),
  publicHostname: document.querySelector("#publicHostname"),
  publicDot: document.querySelector("#publicDot"),
  localDot: document.querySelector("#localDot"),
  frpsControl: document.querySelector("#frpsControl"),
  authMode: document.querySelector("#authMode"),
  certificateExpiry: document.querySelector("#certificateExpiry"),
  upstreamDns: document.querySelector("#upstreamDns"),
  lastQuery: document.querySelector("#lastQuery"),
  serviceError: document.querySelector("#serviceError"),
  frpcLog: document.querySelector("#frpcLog"),
  refreshButton: document.querySelector("#refreshButton"),
  apiDot: document.querySelector("#apiDot"),
  certificateDot: document.querySelector("#certificateDot"),
  dotDot: document.querySelector("#dotDot"),
  frpcDot: document.querySelector("#frpcDot"),
};

function formatUptime(seconds) {
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  if (hours > 0) return `${hours}h ${minutes % 60}m`;
  if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
  return `${seconds}s`;
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
  const labels = { ok: "Operational", warn: "Starting", bad: "Needs attention" };
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

function frpcCopy(data) {
  const state = data.checks.frpc;
  const auth = data.checks.frp_auth_mode;
  if (state === "disabled") return "FRPC is disabled.";
  if (state === "needs-config") return "Set FRP_SERVER_ADDR on Render.";
  if (state === "blocked") return "FRPC is blocked until the DoT listener becomes ready.";
  if (state === "running") return `FRPC process is running with ${auth} authentication.`;
  if (state === "starting") return `FRPC is starting with ${auth} authentication.`;
  if (state === "startup-failed") return data.frpc.last_error || "FRPC failed during startup.";
  if (state === "exited") return data.frpc.last_error || "FRPC exited unexpectedly.";
  return "FRPC has not started.";
}

async function refreshStatus() {
  try {
    const response = await fetch("/api/status", { cache: "no-store" });
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const data = await response.json();
    const certificate = data.certificate;
    const metrics = data.metrics;
    const endpoints = data.endpoints;

    fields.httpStatus.textContent = titleCase(data.checks.http);
    fields.dotStatus.textContent = titleCase(data.checks.dot_listener);
    fields.frpcStatus.textContent = titleCase(data.checks.frpc);
    fields.certificateStatus.textContent = certificate.valid ? "Valid" : "Invalid";
    fields.queryCount.textContent = metrics.dns_queries;
    fields.errorCount.textContent = metrics.dns_errors;
    fields.apiDetail.textContent = `Healthy for ${formatUptime(data.uptime_seconds)} on ${endpoints.http}.`;
    fields.certificateDetail.textContent = certificateCopy(certificate, data.public_dns_hostname || "the configured hostname");
    fields.dotDetail.textContent = `Listener: ${endpoints.dot_local}; upstream: ${endpoints.upstream_resolver}.`;
    fields.frpcDetail.textContent = frpcCopy(data);
    fields.publicHostname.textContent = data.public_dns_hostname || "Not configured";
    fields.publicDot.textContent = endpoints.dot_public || "Not configured";
    fields.localDot.textContent = endpoints.dot_local;
    fields.frpsControl.textContent = endpoints.frps_control || "Not configured";
    fields.authMode.textContent = titleCase(data.checks.frp_auth_mode);
    fields.certificateExpiry.textContent = certificate.expires_at || "Unavailable";
    fields.upstreamDns.textContent = endpoints.upstream_resolver;
    fields.lastQuery.textContent = metrics.last_query_at || "No queries yet";
    fields.serviceError.textContent = certificate.error || data.frpc.last_error || "";
    fields.frpcLog.textContent = data.frpc.last_log ? `Last FRPC log: ${data.frpc.last_log}` : "";

    setDot(fields.apiDot, "ok");
    setDot(fields.certificateDot, certificate.valid ? "ok" : "bad");
    setDot(fields.dotDot, data.checks.dot_listener === "running" || data.checks.dot_listener === "disabled" ? "ok" : "bad");
    setDot(fields.frpcDot, data.checks.frpc === "running" || data.checks.frpc === "disabled" ? "ok" : ["starting", "not-started"].includes(data.checks.frpc) ? "warn" : "bad");

    const starting = ["starting", "not-started"].includes(data.checks.dot_listener) || ["starting", "not-started"].includes(data.checks.frpc);
    setOverall(data.ready ? "ok" : starting ? "warn" : "bad");
  } catch (error) {
    fields.overallStatus.className = "status-pill bad";
    fields.overallStatus.textContent = "Offline";
    fields.apiDetail.textContent = `Status API unavailable: ${error.message}`;
    setDot(fields.apiDot, "bad");
  }
}

fields.refreshButton.addEventListener("click", refreshStatus);
refreshStatus();
setInterval(refreshStatus, 10000);
