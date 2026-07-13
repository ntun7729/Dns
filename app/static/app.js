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
  frpcError: document.querySelector("#frpcError"),
  refreshButton: document.querySelector("#refreshButton"),
};

function formatUptime(seconds) {
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  if (hours > 0) return `${hours}h ${minutes % 60}m`;
  if (minutes > 0) return `${minutes}m ${seconds % 60}s`;
  return `${seconds}s`;
}

function setOverall(ok, warning) {
  fields.overallStatus.className = `status-pill ${ok && !warning ? "ok" : "warn"}`;
  fields.overallStatus.textContent = ok && !warning ? "Operational" : "Needs config";
}

async function refreshStatus() {
  try {
    const response = await fetch("/api/status", { cache: "no-store" });
    const data = await response.json();
    const settings = data.settings;
    const checks = data.checks;
    const metrics = data.metrics;
    const dotEndpoint = `${settings.dot_bind_host}:${settings.dot_port}`;
    const warning = settings.frpc_enabled && !checks.frpc_configured;

    fields.httpStatus.textContent = checks.http;
    fields.dotStatus.textContent = checks.dot;
    fields.frpcStatus.textContent = checks.frpc;
    fields.queryCount.textContent = metrics.dot_queries;
    fields.apiDetail.textContent = `Healthy for ${formatUptime(data.uptime_seconds)} on port ${settings.port}.`;
    fields.dotDetail.textContent = settings.dot_enabled
      ? `TLS DNS listener is bound to ${dotEndpoint} and forwards to ${settings.upstream_dns}:${settings.upstream_dns_port}.`
      : "DNS-over-TLS is disabled by DOT_ENABLED=false.";
    fields.frpcDetail.textContent = checks.frpc_configured
      ? `FRPC is configured to expose local DoT on remote TCP port ${settings.frp_remote_port}.`
      : "Set FRP_SERVER_ADDR and FRP_AUTH_TOKEN on Render to start the FRPC tunnel.";
    fields.httpPort.textContent = settings.port;
    fields.dotPort.textContent = dotEndpoint;
    fields.remotePort.textContent = settings.frp_remote_port;
    fields.upstreamDns.textContent = `${settings.upstream_dns}:${settings.upstream_dns_port}`;
    fields.frpcError.textContent = metrics.frpc_last_error || "";
    setOverall(true, warning);
  } catch (error) {
    fields.overallStatus.className = "status-pill warn";
    fields.overallStatus.textContent = "Offline";
    fields.apiDetail.textContent = `Status API unavailable: ${error.message}`;
  }
}

fields.refreshButton.addEventListener("click", refreshStatus);
refreshStatus();
setInterval(refreshStatus, 10000);
