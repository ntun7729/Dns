from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Any, Mapping, Sequence

from filtering import BlocklistManager
from settings import Settings, now_iso
from certificates import valid_dns_hostname
from telemetry import RuntimeState
from profiles import ProfileStore

STARTED_AT = time.time()


def certificate_warning(certificate: Mapping[str, Any]) -> dict[str, Any]:
    if not certificate.get("valid"):
        return {"level":"critical","renewal_recommended":True,"message":certificate.get("error") or "Certificate is invalid."}
    days=certificate.get("days_remaining")
    if days is None:return {"level":"unknown","renewal_recommended":False,"message":"Certificate expiry could not be determined."}
    if days<15:return {"level":"red","renewal_recommended":True,"message":f"Certificate renewal is urgent: {days} days remaining."}
    if days<=30:return {"level":"yellow","renewal_recommended":True,"message":f"Plan certificate renewal soon: {days} days remaining."}
    return {"level":"green","renewal_recommended":False,"message":f"Certificate is healthy: {days} days remaining."}


def seconds_since(value: str | None) -> int | None:
    if not value:return None
    try:started=datetime.fromisoformat(value.replace("Z","+00:00"))
    except ValueError:return None
    return max(0,int((datetime.now(timezone.utc)-started).total_seconds()))


def upstream_overall_state(upstreams: Sequence[Mapping[str, Any]]) -> str:
    states={item["state"] for item in upstreams}
    if states=={"unknown"} or not states:return "unknown"
    if "healthy" in states and "degraded" in states:return "degraded"
    if "healthy" in states:return "healthy"
    if "degraded" in states:return "failed"
    return "unknown"


def readiness_payload(settings: Settings,runtime: RuntimeState)->dict[str,Any]:
    snapshot=runtime.snapshot();certificate=snapshot["certificate"]
    dot_ready=not settings.dot_enabled or snapshot["dot_state"]=="running"
    certificate_ready=not settings.dot_enabled or bool(certificate.get("valid"))
    hostname_ready=not settings.production or valid_dns_hostname(settings.dot_public_hostname)
    frpc_ready=not settings.frpc_enabled or snapshot["frpc_state"]=="running"
    ready=dot_ready and certificate_ready and hostname_ready and frpc_ready
    return {"ready":ready,"public_dns_hostname":settings.dot_public_hostname or None,"dot_ready":dot_ready,"dot_state":snapshot["dot_state"],"frpc_ready":frpc_ready,"frpc_state":snapshot["frpc_state"],"frp_auth_mode":settings.frp_auth_mode,"certificate_valid":bool(certificate.get("valid")),"certificate_error":certificate.get("error")}


def diagnostics(payload: Mapping[str,Any],filter_status: Mapping[str,Any],settings: Settings)->list[dict[str,str]]:
    findings=[];warning=payload["certificate"]["warning"]
    if warning["level"] in {"critical","red","yellow"}:findings.append({"severity":"critical" if warning["level"]=="critical" else "warning","code":"certificate_renewal","message":warning["message"]})
    frpc_state=payload["checks"]["frpc"]
    if frpc_state not in {"running","disabled"}:
        reconnects=int(payload.get("frpc",{}).get("reconnect_count") or 0);next_retry=float(payload.get("frpc",{}).get("next_retry_seconds") or 0)
        if frpc_state=="reconnecting":message=f"FRPC is reconnecting ({reconnects} reconnect events)."+(f" Retry scheduled in about {next_retry:.1f}s." if next_retry>0 else " FRPC is retrying now.");severity="warning"
        elif frpc_state=="connected":message="FRPC reached FRPS and is waiting for the DoT proxy to become active.";severity="warning"
        else:message=f"FRPC state is {frpc_state}.";severity="critical" if frpc_state in {"exited","startup-failed","stopped"} else "warning"
        findings.append({"severity":severity,"code":"frpc_state","message":message})
    upstream_state=payload["checks"]["upstream"]
    if upstream_state=="failed":findings.append({"severity":"critical","code":"all_upstreams_failed","message":"All configured upstream resolvers are currently degraded."})
    elif upstream_state=="degraded":findings.append({"severity":"warning","code":"upstream_degraded","message":"At least one upstream resolver is cooling down; failover remains available."})
    if payload["metrics"]["dns_errors"]:findings.append({"severity":"warning","code":"dns_errors","message":f"{payload['metrics']['dns_errors']} DNS processing errors have been recorded."})
    if not settings.auth_enabled:findings.append({"severity":"warning","code":"dashboard_auth_disabled","message":"Dashboard controls are disabled until credentials are configured."})
    if filter_status.get("last_error"):findings.append({"severity":"warning","code":"blocklist_update_failed","message":"A blocklist update failed; the previous in-memory list remains active."})
    if not findings:findings.append({"severity":"ok","code":"healthy","message":"All monitored systems are healthy."})
    return findings


def status_payload(settings: Settings,runtime: RuntimeState,profiles: ProfileStore,blocklists: BlocklistManager)->dict[str,Any]:
    snapshot=runtime.snapshot();readiness=readiness_payload(settings,runtime);profile=profiles.active();filtering=blocklists.status(profile);upstreams=runtime.public_upstream_stats(profile.upstreams);upstream_state=upstream_overall_state(upstreams);samples=int(snapshot["upstream_latency_samples"]);total=float(snapshot["upstream_latency_total_ms"]);certificate=dict(snapshot["certificate"]);certificate["warning"]=certificate_warning(certificate);public_endpoint=f"{settings.dot_public_hostname}:{settings.frp_remote_port}" if settings.dot_public_hostname else None
    payload={"service":settings.service_name,"time":now_iso(),"uptime_seconds":max(0,int(time.time()-STARTED_AT)),"ready":readiness["ready"],"public_dns_hostname":settings.dot_public_hostname or None,"checks":{"http":"healthy","dot_listener":snapshot["dot_state"],"frpc":snapshot["frpc_state"],"frp_auth_mode":settings.frp_auth_mode,"certificate":"valid" if certificate.get("valid") else "invalid","upstream":upstream_state},"certificate":certificate,"endpoints":{"http":f"{settings.bind_host}:{settings.port}","dot_local":f"{settings.dot_bind_host}:{settings.dot_port}","dot_public":public_endpoint,"frps_control":f"{settings.frp_server_addr}:{settings.frp_server_port}" if settings.frp_server_addr else None,"upstream_resolver":f"{len(profile.upstreams)} configured resolvers"},"frpc":{"state":snapshot["frpc_state"],"authentication":settings.frp_auth_mode,"started_at":snapshot.get("frpc_started_at"),"connected_at":snapshot.get("frpc_connected_at"),"last_exit_at":snapshot.get("frpc_last_exit_at"),"exit_code":snapshot.get("frpc_exit_code"),"last_error":snapshot.get("frpc_last_error"),"reconnect_count":int(snapshot.get("frpc_reconnect_count",0) or 0),"next_retry_seconds":float(snapshot.get("frpc_next_retry_seconds",0.0) or 0.0),"session_seconds":seconds_since(snapshot.get("frpc_connected_at") or snapshot.get("frpc_started_at")) if snapshot["frpc_state"]=="running" else None},"metrics":{"dns_queries":snapshot["dns_queries"],"dns_errors":snapshot["dns_errors"],"dns_blocked":snapshot["dns_blocked"],"dns_error_types":snapshot["dns_error_types"],"client_disconnects":snapshot["unexpected_disconnects"],"active_connections":snapshot["active_connections"],"peak_connections":snapshot["peak_connections"],"last_query_at":snapshot["last_query_at"],"upstream_last_used":snapshot["upstream_last_used"],"upstream_failovers":snapshot["upstream_failovers"],"upstream_last_latency_ms":snapshot["upstream_last_latency_ms"],"upstream_average_latency_ms":round(total/samples,2) if samples else None,"upstream_samples":samples,"upstream_last_success_at":snapshot["upstream_last_success_at"],"upstream_last_failure_at":snapshot["upstream_last_failure_at"],"upstreams":upstreams},"history":runtime.history.snapshot(),"filtering":filtering,"profile":{"id":profile.id,"name":profile.name,"profile_count":profiles.count()},"access_control":{"enabled":settings.auth_enabled,"controls_available":settings.auth_enabled},"configuration":{**settings.public_config(),"upstream_servers":[endpoint.key for endpoint in profile.upstreams],"upstream_strategy":profile.strategy}}
    payload["diagnostics"]=diagnostics(payload,filtering,settings);return payload
