from __future__ import annotations

import ipaddress
import threading
import urllib.parse
import uuid
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from settings import (
    BLOCKLIST_PRESETS,
    MAX_BLOCKLIST_DOMAINS_PER_SOURCE,
    MAX_CUSTOM_SOURCES,
    MAX_MANUAL_DOMAINS,
    MAX_PROFILES,
    RAW_GITHUB_HOST,
    SUPPORTED_UPSTREAM_STRATEGIES,
    _LABEL_RE,
    Settings,
    UpstreamEndpoint,
    now_iso,
    parse_upstream_servers,
)


@dataclass(frozen=True)
class ProfileSnapshot:
    id: str
    name: str
    upstreams: tuple[UpstreamEndpoint, ...]
    strategy: str
    filter_enabled: bool
    filter_preset: str
    manual_block: frozenset[str]
    allow: frozenset[str]
    custom_blocklist_urls: tuple[str, ...]
    created_at: str
    updated_at: str


def normalize_domain(value: str | None, *, allow_single_label: bool = False) -> str | None:
    if value is None:
        return None
    candidate = value.strip().lower().rstrip(".")
    if not candidate or candidate.startswith(("#", "!", "[")):
        return None
    if candidate.startswith("||"):
        candidate = candidate[2:]
    candidate = candidate.rstrip("^")
    if any(char.isspace() for char in candidate):
        return None
    try:
        candidate = candidate.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    if len(candidate) > 253:
        return None
    labels = candidate.split(".")
    if not allow_single_label and len(labels) < 2:
        return None
    if not all(_LABEL_RE.fullmatch(label) for label in labels):
        return None
    return candidate


def parse_domain_lines(value: str | None) -> frozenset[str]:
    domains: set[str] = set()
    for raw in (value or "").replace(",", "\n").splitlines():
        line = raw.split("#", 1)[0].strip()
        domain = normalize_domain(line)
        if domain:
            domains.add(domain)
    return frozenset(domains)


def validate_raw_github_url(value: str) -> str:
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
        raise ValueError(f"Custom blocklists must be hosted on {RAW_GITHUB_HOST}.")
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
    output: list[str] = []
    seen: set[str] = set()
    for raw in raw_items:
        if not raw.strip():
            continue
        url = validate_raw_github_url(raw)
        if url not in seen:
            output.append(url)
            seen.add(url)
    if len(output) > MAX_CUSTOM_SOURCES:
        raise ValueError(
            f"A maximum of {MAX_CUSTOM_SOURCES} custom GitHub blocklist sources is supported."
        )
    return tuple(output)


class ProfileStore:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.lock = threading.RLock()
        initial = self._new_profile(
            name="Default",
            upstreams=settings.upstreams,
            strategy=settings.upstream_strategy,
            filter_enabled=settings.initial_filter_enabled,
            filter_preset=settings.initial_filter_preset,
            manual_block=parse_domain_lines(settings.initial_manual_block),
            allow=parse_domain_lines(settings.initial_allow),
            custom_blocklist_urls=parse_custom_source_urls(
                settings.initial_custom_sources
            ),
        )
        self.profiles: dict[str, ProfileSnapshot] = {initial.id: initial}
        self.active_id = initial.id
        self._active_snapshot = initial

    @staticmethod
    def _new_profile(
        *,
        name: str,
        upstreams: tuple[UpstreamEndpoint, ...],
        strategy: str,
        filter_enabled: bool,
        filter_preset: str,
        manual_block: frozenset[str],
        allow: frozenset[str],
        custom_blocklist_urls: tuple[str, ...],
        profile_id: str | None = None,
        created_at: str | None = None,
    ) -> ProfileSnapshot:
        timestamp = now_iso()
        return ProfileSnapshot(
            id=profile_id or uuid.uuid4().hex[:12],
            name=name.strip()[:64] or "Profile",
            upstreams=upstreams,
            strategy=strategy,
            filter_enabled=filter_enabled,
            filter_preset=filter_preset,
            manual_block=manual_block,
            allow=allow,
            custom_blocklist_urls=custom_blocklist_urls,
            created_at=created_at or timestamp,
            updated_at=timestamp,
        )

    def active(self) -> ProfileSnapshot:
        return self._active_snapshot

    @staticmethod
    def public(profile: ProfileSnapshot, *, include_domains: bool) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "id": profile.id,
            "name": profile.name,
            "upstream_servers": ",".join(endpoint.key for endpoint in profile.upstreams),
            "upstream_strategy": profile.strategy,
            "filter_enabled": profile.filter_enabled,
            "filter_preset": profile.filter_preset,
            "manual_block_count": len(profile.manual_block),
            "allow_count": len(profile.allow),
            "custom_source_count": len(profile.custom_blocklist_urls),
            "created_at": profile.created_at,
            "updated_at": profile.updated_at,
        }
        if include_domains:
            payload.update(
                {
                    "manual_block_domains": "\n".join(sorted(profile.manual_block)),
                    "allow_domains": "\n".join(sorted(profile.allow)),
                    "custom_blocklist_urls": "\n".join(profile.custom_blocklist_urls),
                }
            )
        return payload

    def _validate(self, data: Mapping[str, Any]) -> dict[str, Any]:
        strategy = str(data.get("upstream_strategy", "")).strip().lower()
        if strategy not in SUPPORTED_UPSTREAM_STRATEGIES:
            raise ValueError("Unsupported upstream strategy.")
        upstreams = parse_upstream_servers(
            str(data.get("upstream_servers", "")).strip(),
            fallback_host=self.settings.upstreams[0].host,
            fallback_port=self.settings.upstreams[0].port,
        )
        preset = str(data.get("filter_preset", "off")).strip().lower()
        if preset not in BLOCKLIST_PRESETS:
            raise ValueError("Unsupported filtering preset.")
        manual_block = parse_domain_lines(str(data.get("manual_block_domains", "")))
        allow = parse_domain_lines(str(data.get("allow_domains", "")))
        if len(manual_block) > MAX_MANUAL_DOMAINS or len(allow) > MAX_MANUAL_DOMAINS:
            raise ValueError(
                f"Manual domain lists are limited to {MAX_MANUAL_DOMAINS:,} entries each."
            )
        return {
            "name": str(data.get("name", "Profile")).strip()[:64] or "Profile",
            "upstreams": upstreams,
            "strategy": strategy,
            "filter_enabled": bool(data.get("filter_enabled", False)),
            "filter_preset": preset,
            "manual_block": manual_block,
            "allow": allow,
            "custom_blocklist_urls": parse_custom_source_urls(
                data.get("custom_blocklist_urls", "")
            ),
        }

    def control_payload(self) -> dict[str, Any]:
        with self.lock:
            profiles = [
                self.public(profile, include_domains=True)
                for profile in self.profiles.values()
            ]
            active_id = self.active_id
        return {
            "runtime_only": True,
            "active_profile_id": active_id,
            "profiles": profiles,
            "filter_presets": [
                {"id": preset_id, "name": details["name"]}
                for preset_id, details in BLOCKLIST_PRESETS.items()
            ],
            "custom_source_host": RAW_GITHUB_HOST,
            "limits": {
                "profiles": MAX_PROFILES,
                "manual_domains_per_list": MAX_MANUAL_DOMAINS,
                "custom_blocklist_sources": MAX_CUSTOM_SOURCES,
            },
        }

    def save(self, data: Mapping[str, Any]) -> dict[str, Any]:
        validated = self._validate(data)
        profile_id = str(data.get("id", "")).strip()
        with self.lock:
            if profile_id:
                existing = self.profiles.get(profile_id)
                if existing is None:
                    raise ValueError("Profile was not found.")
                profile = self._new_profile(
                    **validated,
                    profile_id=profile_id,
                    created_at=existing.created_at,
                )
            else:
                if len(self.profiles) >= MAX_PROFILES:
                    raise ValueError(f"A maximum of {MAX_PROFILES} profiles is supported.")
                profile = self._new_profile(**validated)
                profile_id = profile.id
            self.profiles[profile_id] = profile
            activate = bool(data.get("activate", True))
            if activate:
                self.active_id = profile_id
            if activate or self.active_id == profile_id:
                self._active_snapshot = profile
        return self.control_payload()

    def count(self) -> int:
        with self.lock:
            return len(self.profiles)

    def activate(self, profile_id: str) -> dict[str, Any]:
        with self.lock:
            profile = self.profiles.get(profile_id)
            if profile is None:
                raise ValueError("Profile was not found.")
            self.active_id = profile_id
            self._active_snapshot = profile
        return self.control_payload()

    def duplicate(self, profile_id: str) -> dict[str, Any]:
        with self.lock:
            source = self.profiles.get(profile_id)
            if source is None:
                raise ValueError("Profile was not found.")
            if len(self.profiles) >= MAX_PROFILES:
                raise ValueError(f"A maximum of {MAX_PROFILES} profiles is supported.")
            profile = self._new_profile(
                name=f"{source.name} Copy",
                upstreams=source.upstreams,
                strategy=source.strategy,
                filter_enabled=source.filter_enabled,
                filter_preset=source.filter_preset,
                manual_block=source.manual_block,
                allow=source.allow,
                custom_blocklist_urls=source.custom_blocklist_urls,
            )
            self.profiles[profile.id] = profile
            self.active_id = profile.id
            self._active_snapshot = profile
        return self.control_payload()

    def delete(self, profile_id: str) -> dict[str, Any]:
        with self.lock:
            if profile_id not in self.profiles:
                raise ValueError("Profile was not found.")
            if len(self.profiles) == 1:
                raise ValueError("The final profile cannot be deleted.")
            del self.profiles[profile_id]
            if self.active_id == profile_id:
                self.active_id = next(iter(self.profiles))
                self._active_snapshot = self.profiles[self.active_id]
        return self.control_payload()

    def export(self) -> dict[str, Any]:
        with self.lock:
            return {
                "format": "dns-dashboard-profiles-v1",
                "active_profile_id": self.active_id,
                "profiles": [
                    self.public(profile, include_domains=True)
                    for profile in self.profiles.values()
                ],
            }

    def import_export(self, data: Mapping[str, Any]) -> dict[str, Any]:
        if data.get("format") != "dns-dashboard-profiles-v1":
            raise ValueError("Unsupported profile export format.")
        raw_profiles = data.get("profiles")
        if not isinstance(raw_profiles, list) or not raw_profiles:
            raise ValueError("Profile export contains no profiles.")
        if len(raw_profiles) > MAX_PROFILES:
            raise ValueError(f"A maximum of {MAX_PROFILES} profiles is supported.")

        imported: dict[str, ProfileSnapshot] = {}
        for raw in raw_profiles:
            if not isinstance(raw, dict):
                raise ValueError("Each imported profile must be an object.")
            validated = self._validate(raw)
            profile_id = str(raw.get("id", "")).strip() or uuid.uuid4().hex[:12]
            while profile_id in imported:
                profile_id = uuid.uuid4().hex[:12]
            imported[profile_id] = self._new_profile(
                **validated,
                profile_id=profile_id,
                created_at=str(raw.get("created_at", "")).strip() or None,
            )

        requested_active = str(data.get("active_profile_id", "")).strip()
        with self.lock:
            self.profiles = imported
            self.active_id = (
                requested_active if requested_active in imported else next(iter(imported))
            )
            self._active_snapshot = self.profiles[self.active_id]
        return self.control_payload()


def _line_domains(line: str) -> Iterable[str]:
    stripped = line.split("#", 1)[0].strip()
    if not stripped or stripped.startswith(("!", "[")):
        return ()
    if stripped.startswith("||"):
        domain = normalize_domain(stripped)
        return (domain,) if domain else ()

    tokens = stripped.split()
    if not tokens:
        return ()
    try:
        ipaddress.ip_address(tokens[0])
        candidates = tokens[1:]
    except ValueError:
        candidates = tokens[:1]
    output: list[str] = []
    for token in candidates:
        domain = normalize_domain(token)
        if domain:
            output.append(domain)
    return output


def parse_blocklist_text(text: str) -> frozenset[str]:
    domains: set[str] = set()
    for raw_line in text.splitlines():
        for domain in _line_domains(raw_line):
            domains.add(domain)
            if len(domains) > MAX_BLOCKLIST_DOMAINS_PER_SOURCE:
                raise ValueError(
                    "Blocklist contains more domains than the in-memory safety limit."
                )
    return frozenset(domains)
