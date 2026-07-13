#!/usr/bin/env python3
"""Dashboard v2.4: custom raw GitHub filters and clearer connection telemetry."""

from __future__ import annotations

import asyncio
import os
import ssl
import threading
import urllib.parse
import urllib.request
from typing import Any

import enhanced_main as enhanced
import main as core
import managed_main as managed

RAW_GITHUB_HOST = "raw.githubusercontent.com"
MAX_CUSTOM_SOURCES = 5
MAX_CUSTOM_BLOCKLIST_BYTES = 12 * 1024 * 1024

CUSTOM_SOURCE_LOCK = threading.RLock()
CUSTOM_SOURCE_CACHE: dict[str, dict[str, Any]] = {}

_ORIGINAL_NEW_PROFILE = managed._new_profile
_ORIGINAL_PROFILE_PUBLIC = managed._profile_public
_ORIGINAL_ACTIVE_PROFILE_COPY = managed._active_profile_copy
_ORIGINAL_VALIDATE_PROFILE_DATA = managed._validate_profile_data
_ORIGINAL_REFRESH_BLOCKLIST_ASYNC = managed.refresh_blocklist_async


def validate_raw_github_url(value: str) -> str:
    """Return a canonical, HTTPS-only raw.githubusercontent.com URL."""
    candidate = value.strip()
    if not candidate:
        raise ValueError("Blocklist URL cannot be empty.")
    try:
        parsed = urllib.parse.urlsplit(candidate)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Blocklist URL is invalid.") from exc
    if parsed.scheme.lower() != "https":
        raise ValueError("Custom blocklists must use HTTPS.")
    if parsed.hostname != RAW_GITHUB_HOST:
        raise ValueError(
            f"Custom blocklists must be hosted on {RAW_GITHUB_HOST}."
        )
    if parsed.username or parsed.password or port not in {None, 443}:
        raise ValueError("Blocklist URL contains unsupported credentials or port.")
    if parsed.query or parsed.fragment:
        raise ValueError("Blocklist URL must not contain a query string or fragment.")
    path_parts = [part for part in parsed.path.split("/") if part]
    if len(path_parts) < 4:
        raise ValueError(
            "Use a complete raw GitHub file URL containing owner, repository, ref, and path."
        )
    return urllib.parse.urlunsplit(("https", RAW_GITHUB_HOST, parsed.path, "", ""))


def parse_custom_source_urls(value: Any) -> tuple[str, ...]:
    if isinstance(value, (list, tuple)):
        raw_items = [str(item) for item in value]
    else:
        raw_items = str(value or "").replace(",", "\n").splitlines()
    urls: list[str] = []
    seen: set[str] = set()
    for raw in raw_items:
        if not raw.strip():
            continue
        url = validate_raw_github_url(raw)
        if url not in seen:
            urls.append(url)
            seen.add(url)
    if len(urls) > MAX_CUSTOM_SOURCES:
        raise ValueError(
            f"A maximum of {MAX_CUSTOM_SOURCES} custom GitHub blocklist sources is supported."
        )
    return tuple(urls)


def _initial_custom_sources() -> tuple[str, ...]:
    try:
        return parse_custom_source_urls(os.getenv("CUSTOM_BLOCKLIST_URLS", ""))
    except ValueError:
        return ()


def _ensure_profile_sources() -> None:
    initial = _initial_custom_sources()
    with managed.PROFILE_LOCK:
        for profile in managed.PROFILES.values():
            profile.setdefault("custom_blocklist_urls", initial)


def new_profile(
    *,
    name: str,
    upstreams: tuple[enhanced.UpstreamEndpoint, ...] | None = None,
    strategy: str | None = None,
    filter_enabled: bool | None = None,
    filter_preset: str | None = None,
    manual_block: set[str] | None = None,
    allow: set[str] | None = None,
    custom_blocklist_urls: tuple[str, ...] | None = None,
    profile_id: str | None = None,
) -> dict[str, Any]:
    profile = _ORIGINAL_NEW_PROFILE(
        name=name,
        upstreams=upstreams,
        strategy=strategy,
        filter_enabled=filter_enabled,
        filter_preset=filter_preset,
        manual_block=manual_block,
        allow=allow,
        profile_id=profile_id,
    )
    profile["custom_blocklist_urls"] = tuple(
        _initial_custom_sources()
        if custom_blocklist_urls is None
        else custom_blocklist_urls
    )
    return profile


def profile_public(profile: dict[str, Any], *, include_domains: bool) -> dict[str, Any]:
    payload = _ORIGINAL_PROFILE_PUBLIC(profile, include_domains=include_domains)
    urls = tuple(profile.get("custom_blocklist_urls", ()))
    payload["custom_source_count"] = len(urls)
    if include_domains:
        payload["custom_blocklist_urls"] = "\n".join(urls)
    return payload


def active_profile_copy() -> dict[str, Any]:
    profile = _ORIGINAL_ACTIVE_PROFILE_COPY()
    profile["custom_blocklist_urls"] = tuple(
        profile.get("custom_blocklist_urls", ())
    )
    return profile


def validate_profile_data(data: dict[str, Any]) -> dict[str, Any]:
    validated = _ORIGINAL_VALIDATE_PROFILE_DATA(data)
    validated["custom_blocklist_urls"] = parse_custom_source_urls(
        data.get("custom_blocklist_urls", "")
    )
    return validated


def duplicate_profile(profile_id: str) -> dict[str, Any]:
    with managed.PROFILE_LOCK:
        if profile_id not in managed.PROFILES:
            raise ValueError("Profile was not found.")
        source = managed.PROFILES[profile_id]
        if len(managed.PROFILES) >= managed.MAX_PROFILES:
            raise ValueError(
                f"A maximum of {managed.MAX_PROFILES} profiles is supported."
            )
        profile = new_profile(
            name=f"{source['name']} Copy",
            upstreams=tuple(source["upstreams"]),
            strategy=source["strategy"],
            filter_enabled=source["filter_enabled"],
            filter_preset=source["filter_preset"],
            manual_block=set(source["manual_block"]),
            allow=set(source["allow"]),
            custom_blocklist_urls=tuple(source.get("custom_blocklist_urls", ())),
        )
        managed.PROFILES[profile["id"]] = profile
    return managed.activate_profile(profile["id"])


def _cache_for(url: str) -> dict[str, Any]:
    with CUSTOM_SOURCE_LOCK:
        return CUSTOM_SOURCE_CACHE.setdefault(
            url,
            {
                "domains": set(),
                "loading": False,
                "last_updated_at": None,
                "last_error": None,
            },
        )


def _download_custom_blocklist(url: str) -> set[str]:
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "DNS-Dashboard/2.4 custom blocklist updater"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        data = response.read(MAX_CUSTOM_BLOCKLIST_BYTES + 1)
    if len(data) > MAX_CUSTOM_BLOCKLIST_BYTES:
        raise ValueError("Custom blocklist exceeds the 12 MiB size limit.")
    return managed._parse_blocklist_text(data.decode("utf-8", errors="ignore"))


def refresh_custom_source_async(url: str) -> None:
    canonical = validate_raw_github_url(url)
    cache = _cache_for(canonical)
    with CUSTOM_SOURCE_LOCK:
        if cache["loading"]:
            return
        cache["loading"] = True
        cache["last_error"] = None

    def worker() -> None:
        try:
            domains = _download_custom_blocklist(canonical)
            if not domains:
                raise ValueError("Downloaded blocklist contained no valid domains.")
            with CUSTOM_SOURCE_LOCK:
                current = _cache_for(canonical)
                current["domains"] = domains
                current["last_updated_at"] = core.now_iso()
                current["last_error"] = None
        except Exception as exc:  # noqa: BLE001 - safe status text only.
            with CUSTOM_SOURCE_LOCK:
                _cache_for(canonical)["last_error"] = str(exc)[:300]
        finally:
            with CUSTOM_SOURCE_LOCK:
                _cache_for(canonical)["loading"] = False

    threading.Thread(target=worker, daemon=True).start()


def refresh_blocklist_async(preset: str) -> None:
    _ORIGINAL_REFRESH_BLOCKLIST_ASYNC(preset)
    profile = active_profile_copy()
    for url in profile.get("custom_blocklist_urls", ()):
        refresh_custom_source_async(url)


def _custom_source_contains(url: str, suffixes: tuple[str, ...]) -> bool:
    with CUSTOM_SOURCE_LOCK:
        domains = _cache_for(url)["domains"]
        return any(suffix in domains for suffix in suffixes)


def domain_is_blocked(domain: str) -> bool:
    profile = active_profile_copy()
    if not profile["filter_enabled"]:
        return False
    suffixes = managed._domain_suffixes(domain)
    if any(suffix in profile["allow"] for suffix in suffixes):
        return False
    if any(suffix in profile["manual_block"] for suffix in suffixes):
        return True
    preset = str(profile["filter_preset"])
    with managed.FILTER_LOCK:
        preset_domains = managed.BLOCKLIST_CACHE.get(preset, {}).get(
            "domains", set()
        )
        if any(suffix in preset_domains for suffix in suffixes):
            return True
    return any(
        _custom_source_contains(url, suffixes)
        for url in profile.get("custom_blocklist_urls", ())
    )


def _custom_source_status(url: str) -> dict[str, Any]:
    cache = _cache_for(url)
    with CUSTOM_SOURCE_LOCK:
        error = cache["last_error"]
        if cache["loading"]:
            state = "loading"
        elif error:
            state = "error"
        elif cache["domains"]:
            state = "ready"
        else:
            state = "waiting"
        return {
            "url": url,
            "state": state,
            "domain_count": len(cache["domains"]),
            "loading": bool(cache["loading"]),
            "last_updated_at": cache["last_updated_at"],
            "last_error": error,
        }


def filtering_status() -> dict[str, Any]:
    status = managed._original_filtering_status()  # type: ignore[attr-defined]
    profile = active_profile_copy()
    sources = [
        _custom_source_status(url)
        for url in profile.get("custom_blocklist_urls", ())
    ]
    custom_entries = sum(int(source["domain_count"]) for source in sources)
    errors = [source["last_error"] for source in sources if source["last_error"]]
    status["custom_sources"] = sources
    status["custom_source_count"] = len(sources)
    status["custom_loaded_entries"] = custom_entries
    status["downloaded_domains"] = int(status["downloaded_domains"]) + custom_entries
    status["loading"] = bool(status["loading"]) or any(
        source["loading"] for source in sources
    )
    if not status["last_error"] and errors:
        status["last_error"] = errors[0]
    return status


def control_payload() -> dict[str, Any]:
    payload = managed._original_control_payload()  # type: ignore[attr-defined]
    payload["limits"]["custom_blocklist_sources"] = MAX_CUSTOM_SOURCES
    payload["custom_source_host"] = RAW_GITHUB_HOST
    return payload


def _record_unexpected_disconnect() -> None:
    with core.RUNTIME_LOCK:
        core.RUNTIME["client_disconnects"] = int(
            core.RUNTIME.get("client_disconnects", 0)
        ) + 1


def should_count_incomplete_read(exc: asyncio.IncompleteReadError) -> bool:
    """A zero-byte EOF is a normal persistent-connection close."""
    return bool(exc.partial)


async def handle_dot(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    settings: core.Settings = core.SETTINGS,
) -> None:
    enhanced._record_connection_delta(1)
    try:
        while True:
            header = await reader.readexactly(2)
            length = int.from_bytes(header, "big")
            if length <= 0 or length > 4096:
                raise ValueError(f"Invalid DNS message length: {length}")
            payload = await reader.readexactly(length)
            domain, question_end = managed.parse_dns_question(payload)
            blocked = domain_is_blocked(domain)
            if blocked:
                response = managed.build_nxdomain_response(payload, question_end)
                with managed.FILTER_LOCK:
                    managed.BLOCKED_QUERIES += 1
            else:
                response = await managed.forward_dns_query(payload, settings)
            writer.write(len(response).to_bytes(2, "big") + response)
            await writer.drain()
            with core.RUNTIME_LOCK:
                core.RUNTIME["dns_queries"] += 1
                core.RUNTIME["last_query_at"] = core.now_iso()
            managed._record_history(queries=1, blocked=1 if blocked else 0)
    except asyncio.IncompleteReadError as exc:
        if should_count_incomplete_read(exc):
            _record_unexpected_disconnect()
    except (ConnectionResetError, BrokenPipeError, ssl.SSLError, ConnectionError):
        _record_unexpected_disconnect()
    except Exception as exc:  # noqa: BLE001 - aggregate telemetry only.
        safe_error = core.redact_text(str(exc), settings)
        enhanced._record_dns_error(enhanced.classify_dns_error(exc), safe_error)
        managed._record_history(errors=1)
    finally:
        enhanced._record_connection_delta(-1)
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, ssl.SSLError):
            pass


_ensure_profile_sources()
managed._original_filtering_status = managed.filtering_status  # type: ignore[attr-defined]
managed._original_control_payload = managed.control_payload  # type: ignore[attr-defined]
managed._new_profile = new_profile
managed._profile_public = profile_public
managed._active_profile_copy = active_profile_copy
managed._validate_profile_data = validate_profile_data
managed.duplicate_profile = duplicate_profile
managed.refresh_blocklist_async = refresh_blocklist_async
managed.domain_is_blocked = domain_is_blocked
managed.filtering_status = filtering_status
managed.control_payload = control_payload
managed.handle_dot = handle_dot
enhanced.handle_dot = handle_dot
core.handle_dot = handle_dot
core.DashboardHandler.server_version = "DnsDashboard/2.4"


if __name__ == "__main__":
    managed.start_managed_services()
    core.main()
