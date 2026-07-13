const fields = {
  overallStatus: document.querySelector("#overallStatus"),
  httpStatus: document.querySelector("#httpStatus"),
  dotStatus: document.querySelector("#dotStatus"),
  frpcStatus: document.querySelector("#frpcStatus"),
  queryCount: document.querySelector("#queryCount"),
  apiDetail: document.querySelector("#apiDetail"),
  dotDetail: document.querySelector("#dotDetail"),
  frpcDetail: document.querySelector("#frpcDetail"),
  httpPort: document.querySelector("#httpPort"),
  dotPort: document.querySelector("#dotPort"),
  remotePort: document.querySelector("#remotePort"),
  upstreamDns: document.querySelector("#upstreamDns"),
  lastQuery: document.querySelector("#lastQuery"),
  frpcError: document.querySelector("#frpcError"),
  frpcLog: document.querySelector("#frpcLog"),
  refreshButton: document.querySelector("#refreshButton"),
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
  return String(value)
    .split("-")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}

function setDot(element, state) {
  element.className = `dot ${state}`;
}

function setOverall(state) {
  const labels = {
    ok: "Operational",
    warn: "Needs config",
    bad: "Needs attention",
  };
  fields.overallStatus.className = `status-pill ${state}`;
  fields.overallStatus.textContent = labels[state];
}

function frpcCopy(checks, settings, metrics) {
  if (!settings.frpc_enabled) return "FRPC is disabled by FRPC_ENABLED=false.";
  if (!checks.frpc_configured) return "Set FRP_SERVER_ADDR and FRP_AUTH_TOKEN on Render to start the FRPC tunnel.";
  if (checks.frpc === "running") return `FRPC is exposing local DoT on remote TCP port ${settings.frp_remote_port}.`;
  if (checks.frpc === "exited") return `FRPC started but is no longer running${metrics.frpc_exit_code === null ? "." : `; exit code ${metrics.frpc_exit_code}.`}`;
  return "FRPC is configured but has not reported a running process yet.";
}

async function refreshStatus() {
  try {
    const response = await fetch("/api/status", { cache: "no-store" });
    const data = await response.json();
    const settings = data.settings;
    const checks = data.checks;
    const metrics = data.metrics;
    const endpoints = data.endpoints;
    const warning = settings.frpc_enabled && checks.frpc !== "running";
    const failure = checks.frpc === "exited";

    fields.httpStatus.textContent = titleCase(checks.http);
    fields.dotStatus.textContent = titleCase(checks.dot);
    fields.frpcStatus.textContent = titleCase(checks.frpc);
    fields.queryCount.textContent = metrics.dot_queries;
    fields.apiDetail.textContent = `Healthy for ${formatUptime(data.uptime_seconds)} on ${endpoints.http}.`;
    fields.dotDetail.textContent = settings.dot_enabled
      ? `TLS DNS listener is ${checks.dot} at ${endpoints.dot_local} and forwards to ${endpoints.upstream_dns}.`
      : "DNS-over-TLS is disabled by DOT_ENABLED=false.";
    fields.frpcDetail.textContent = frpcCopy(checks, settings, metrics);
    fields.httpPort.textContent = endpoints.http;
    fields.dotPort.textContent = endpoints.dot_local;
    fields.remotePort.textContent = `tcp/${endpoints.dot_remote_port}`;
    fields.upstreamDns.textContent = endpoints.upstream_dns;
    fields.lastQuery.textContent = metrics.last_query_at || "No queries yet";
    fields.frpcError.textContent = metrics.frpc_last_error || "";
    fields.frpcLog.textContent = metrics.frpc_last_log ? `Last FRPC log: ${metrics.frpc_last_log}` : "";
    setDot(fields.dotDot, checks.dot === "ready" || checks.dot === "disabled" ? "ok" : "warn");
    setDot(fields.frpcDot, checks.frpc === "running" || checks.frpc === "disabled" ? "ok" : failure ? "bad" : "warn");
    setOverall(failure ? "bad" : warning ? "warn" : "ok");
  } catch (error) {
    fields.overallStatus.className = "status-pill bad";
    fields.overallStatus.textContent = "Offline";
    fields.apiDetail.textContent = `Status API unavailable: ${error.message}`;
  }
}

fields.refreshButton.addEventListener("click", refreshStatus);
refreshStatus();
setInterval(refreshStatus, 10000);
