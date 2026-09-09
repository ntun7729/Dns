from __future__ import annotations

import threading
import time
import urllib.parse
import urllib.request
from typing import Any, Mapping

from settings import (
    BLOCKLIST_PRESETS,
    HAGEZI_LIGHT_URL,
    MAX_CUSTOM_BLOCKLIST_BYTES,
    MAX_PRESET_BLOCKLIST_BYTES,
    MAX_TOTAL_ACTIVE_BLOCKLIST_DOMAINS,
    RAW_GITHUB_HOST,
    Settings,
    now_iso,
)
from telemetry import History, RuntimeState
from profiles import ProfileSnapshot, ProfileStore, parse_blocklist_text


def domain_suffixes(domain: str) -> tuple[str, ...]:
    if domain == ".":
        return ()
    labels = domain.split(".")
    return tuple(".".join(labels[index:]) for index in range(len(labels)))


class BlocklistManager:
    def __init__(
        self,
        settings: Settings,
        profiles: ProfileStore,
        runtime: RuntimeState | None = None,
    ) -> None:
        self.settings = settings
        self.profiles = profiles
        self.runtime = runtime or RuntimeState(History(settings.history_minutes))
        self.lock = threading.RLock()
        self.caches: dict[str, dict[str, Any]] = {}
        self.stop_event = threading.Event()
        self.background_thread: threading.Thread | None = None

    def _cache(self, url: str) -> dict[str, Any]:
        with self.lock:
            return self.caches.setdefault(
                url,
                {
                    "domains": frozenset(),
                    "loading": False,
                    "last_updated_at": None,
                    "last_updated_epoch": 0.0,
                    "last_error": None,
                },
            )

    def _source_urls(self, profile: ProfileSnapshot) -> tuple[str, ...]:
        urls: list[str] = []
        preset_url = BLOCKLIST_PRESETS[profile.filter_preset]["url"]
        candidates = (
            ((str(preset_url),) if preset_url else ())
            + profile.custom_blocklist_urls
        )
        for url in candidates:
            if url not in urls:
                urls.append(url)
        return tuple(urls)

    def _prune_caches(self, profile: ProfileSnapshot) -> None:
        active_urls = set(self._source_urls(profile)) if profile.filter_enabled else set()
        with self.lock:
            stale_urls = [
                url
                for url, cache in self.caches.items()
                if url not in active_urls and not cache.get("loading")
            ]
            for url in stale_urls:
                self.caches.pop(url, None)

    def _is_stale(self, cache: Mapping[str, Any]) -> bool:
        age = time.time() - float(cache.get("last_updated_epoch", 0.0))
        return not cache.get("domains") or age >= self.settings.filter_update_hours * 3600

    def _download(self, url: str) -> frozenset[str]:
        limit = (
            MAX_CUSTOM_BLOCKLIST_BYTES
            if urllib.parse.urlsplit(url).hostname == RAW_GITHUB_HOST
            and url != HAGEZI_LIGHT_URL
            else MAX_PRESET_BLOCKLIST_BYTES
        )
        request = urllib.request.Request(
            url,
            headers={"User-Agent": "DNS-Dashboard/4.0 blocklist updater"},
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            content_length = response.headers.get("Content-Length")
            if content_length:
                try:
                    declared_size = int(content_length)
                except (TypeError, ValueError):
                    declared_size = None
                if declared_size is not None and declared_size > limit:
                    raise ValueError("Blocklist exceeds the download size limit.")
            data = response.read(limit + 1)
        if len(data) > limit:
            raise ValueError("Blocklist exceeds the download size limit.")
        domains = parse_blocklist_text(data.decode("utf-8", errors="ignore"))
        if not domains:
            raise ValueError("Downloaded blocklist contained no valid domains.")
        return domains

    def refresh_url_async(self, url: str, *, force: bool = False) -> None:
        cache = self._cache(url)
        with self.lock:
            if cache["loading"]:
                return
            if not force and not self._is_stale(cache):
                return
            cache["loading"] = True
            cache["last_error"] = None

        def worker() -> None:
            try:
                domains = self._download(url)
                with self.lock:
                    active_urls = self._source_urls(self.profiles.active())
                    if url in active_urls:
                        active_total = len(domains) + sum(
                            len(self._cache(other)["domains"])
                            for other in active_urls
                            if other != url
                        )
                        if active_total > MAX_TOTAL_ACTIVE_BLOCKLIST_DOMAINS:
                            raise ValueError(
                                "Active blocklists exceed the total in-memory domain limit."
                            )
                    current = self._cache(url)
                    current["domains"] = domains
                    current["last_updated_at"] = now_iso()
                    current["last_updated_epoch"] = time.time()
                    current["last_error"] = None
            except Exception as exc:
                with self.lock:
                    self._cache(url)["last_error"] = str(exc)[:300]
            finally:
                with self.lock:
                    self._cache(url)["loading"] = False

        threading.Thread(target=worker, daemon=True).start()

    def refresh_profile(self, profile: ProfileSnapshot, *, force: bool = False) -> None:
        self._prune_caches(profile)
        if not profile.filter_enabled:
            return
        for url in self._source_urls(profile):
            self.refresh_url_async(url, force=force)

    def domain_is_blocked(self, domain: str, profile: ProfileSnapshot) -> bool:
        if not profile.filter_enabled or domain == ".":
            return False
        suffixes = domain_suffixes(domain)
        if any(suffix in profile.allow for suffix in suffixes):
            return False
        if any(suffix in profile.manual_block for suffix in suffixes):
            return True

        with self.lock:
            domain_sets = tuple(
                self._cache(url)["domains"] for url in self._source_urls(profile)
            )
        return any(
            suffix in domains for domains in domain_sets for suffix in suffixes
        )

    def status(self, profile: ProfileSnapshot) -> dict[str, Any]:
        sources: list[dict[str, Any]] = []
        total_domains = 0
        loading = False
        first_error: str | None = None
        with self.lock:
            for url in self._source_urls(profile):
                cache = self._cache(url)
                error = cache["last_error"]
                state = (
                    "loading"
                    if cache["loading"]
                    else "error"
                    if error
                    else "ready"
                    if cache["domains"]
                    else "waiting"
                )
                source = {
                    "url": url,
                    "state": state,
                    "domain_count": len(cache["domains"]),
                    "loading": bool(cache["loading"]),
                    "last_updated_at": cache["last_updated_at"],
                    "last_error": error,
                }
                sources.append(source)
                total_domains += source["domain_count"]
                loading = loading or source["loading"]
                first_error = first_error or error
        preset = BLOCKLIST_PRESETS[profile.filter_preset]
        custom = [source for source in sources if source["url"] != preset["url"]]
        return {
            "enabled": profile.filter_enabled,
            "preset": profile.filter_preset,
            "preset_name": preset["name"],
            "source": preset["url"],
            "downloaded_domains": total_domains,
            "manual_block_domains": len(profile.manual_block),
            "allow_domains": len(profile.allow),
            "blocked_queries": self.runtime.snapshot()["dns_blocked"],
            "loading": loading,
            "last_updated_at": max(
                (source["last_updated_at"] for source in sources if source["last_updated_at"]),
                default=None,
            ),
            "last_error": first_error,
            "custom_sources": custom,
            "custom_source_count": len(custom),
            "custom_loaded_entries": sum(source["domain_count"] for source in custom),
        }

    def start(self) -> None:
        self.refresh_profile(self.profiles.active())
        if self.background_thread and self.background_thread.is_alive():
            return

        def loop() -> None:
            while not self.stop_event.wait(min(300, self.settings.filter_update_hours * 3600)):
                self.refresh_profile(self.profiles.active())

        self.background_thread = threading.Thread(target=loop, daemon=True)
        self.background_thread.start()
