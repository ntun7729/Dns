from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
import threading
import time

from filtering import BlocklistManager
from settings import MAX_DNS_MESSAGE_BYTES, Settings, UpstreamEndpoint
from certificates import prepare_tls_material, redact_text
from telemetry import RuntimeState, classify_dns_error
from profiles import ProfileSnapshot, ProfileStore


_RESOLVER_CACHE: dict[str, tuple[list[tuple], float]] = {}
_RESOLVER_CACHE_LOCK = threading.Lock()
RESOLVER_CACHE_TTL = 300.0

# Many container platforms either rate-limit or block outbound UDP/53 while
# allowing TCP/53. Probe UDP briefly, then fall back to TCP within the same
# configured upstream timeout budget. Remember working TCP preference so every
# subsequent DNS query does not pay the UDP timeout penalty.
UDP_PROBE_TIMEOUT_SECONDS = 0.35
TRANSPORT_PREFERENCE_TTL_SECONDS = 300.0
_TRANSPORT_PREFERENCE: dict[str, tuple[str, float]] = {}
_TRANSPORT_PREFERENCE_LOCK = threading.Lock()

# Keep the application-level DNS cache intentionally small. It exists to absorb
# repeat lookups, not to become an unbounded recursive-resolver cache.
MAX_DNS_CACHE_ENTRIES = 4096
MAX_DNS_CACHE_RESPONSE_BYTES = 8192
MAX_DNS_CACHE_TTL_SECONDS = 300.0
MAX_INFLIGHT_QUERIES_PER_CONNECTION = 64
MAX_DNS_NAME_POINTER_JUMPS = 32
DOT_TLS_HANDSHAKE_TIMEOUT_SECONDS = 5.0
DOT_TLS_SHUTDOWN_TIMEOUT_SECONDS = 1.0
_DNS_CACHE: dict[tuple[str, str, str, bytes], tuple[bytes, float]] = {}
_DNS_CACHE_LOCK = threading.Lock()


def _profile_cache_key(profile: ProfileSnapshot) -> tuple[str, str]:
    return profile.id, profile.updated_at


def get_cached_dns_response(
    profile: ProfileSnapshot,
    domain: str,
    qtype_class: bytes,
    transaction_id: bytes,
) -> bytes | None:
    profile_id, profile_revision = _profile_cache_key(profile)
    key = (profile_id, profile_revision, domain, qtype_class)
    now = time.monotonic()
    with _DNS_CACHE_LOCK:
        cached = _DNS_CACHE.get(key)
        if cached is None:
            return None
        response, expiry = cached
        if now < expiry:
            return transaction_id + response[2:]
        _DNS_CACHE.pop(key, None)
    return None


def cache_dns_response(
    profile: ProfileSnapshot,
    domain: str,
    qtype_class: bytes,
    response: bytes,
    question_end: int,
) -> None:
    if len(response) < 4 or len(response) > MAX_DNS_CACHE_RESPONSE_BYTES:
        return
    rcode = response[3] & 0x0F
    if rcode not in (0, 3):
        return

    ttl = 10.0
    try:
        if len(response) > question_end + 10 and response[question_end] & 0xC0 == 0xC0:
            ttl_bytes = response[question_end + 6 : question_end + 10]
            parsed_ttl = int.from_bytes(ttl_bytes, "big")
            if parsed_ttl >= 1:
                ttl = min(float(parsed_ttl), MAX_DNS_CACHE_TTL_SECONDS)
    except (IndexError, ValueError):
        pass

    profile_id, profile_revision = _profile_cache_key(profile)
    key = (profile_id, profile_revision, domain, qtype_class)
    now = time.monotonic()
    with _DNS_CACHE_LOCK:
        if len(_DNS_CACHE) >= MAX_DNS_CACHE_ENTRIES:
            for stale_key, (_payload, expiry) in tuple(_DNS_CACHE.items()):
                if expiry <= now:
                    _DNS_CACHE.pop(stale_key, None)
            while len(_DNS_CACHE) >= MAX_DNS_CACHE_ENTRIES:
                try:
                    oldest = next(iter(_DNS_CACHE))
                except StopIteration:
                    break
                _DNS_CACHE.pop(oldest, None)
        _DNS_CACHE[key] = (response, now + ttl)


def _resolve_endpoint(host: str, port: int, socktype: int) -> list[tuple]:
    try:
        ip = ipaddress.ip_address(host)
        family = socket.AF_INET6 if ip.version == 6 else socket.AF_INET
        sockaddr = (host, port, 0, 0) if family == socket.AF_INET6 else (host, port)
        return [(family, socktype, 0, "", sockaddr)]
    except ValueError:
        pass

    cache_key = f"{host}:{port}:{socktype}"
    now = time.monotonic()
    with _RESOLVER_CACHE_LOCK:
        cached = _RESOLVER_CACHE.get(cache_key)
        if cached is not None:
            cached_addrs, expiry = cached
            if now < expiry:
                return cached_addrs

    try:
        addresses = socket.getaddrinfo(host, port, type=socktype)
        addresses = sorted(addresses, key=lambda addr: 0 if addr[0] == socket.AF_INET else 1)
    except OSError as exc:
        with _RESOLVER_CACHE_LOCK:
            cached = _RESOLVER_CACHE.get(cache_key)
            if cached is not None:
                return cached[0]
        raise exc

    with _RESOLVER_CACHE_LOCK:
        _RESOLVER_CACHE[cache_key] = (addresses, now + RESOLVER_CACHE_TTL)
    return addresses


def _recv_exact(sock: socket.socket, length: int) -> bytes:
    chunks: list[bytes] = []
    remaining = length
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise OSError("Upstream TCP connection closed before the DNS response completed.")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _validate_upstream_response(payload: bytes, response: bytes) -> None:
    if len(response) < 12:
        raise OSError("Upstream returned a truncated DNS header.")
    if len(payload) >= 2 and response[:2] != payload[:2]:
        raise OSError("Upstream returned a mismatched DNS transaction ID.")
    if not int.from_bytes(response[2:4], "big") & 0x8000:
        raise OSError("Upstream returned a DNS message without the response bit set.")


def _remaining_timeout(deadline: float, *, minimum: float = 0.05) -> float:
    return max(minimum, deadline - time.monotonic())


def _transport_preference(endpoint: UpstreamEndpoint) -> str | None:
    now = time.monotonic()
    with _TRANSPORT_PREFERENCE_LOCK:
        cached = _TRANSPORT_PREFERENCE.get(endpoint.key)
        if cached is None:
            return None
        transport, expiry = cached
        if now >= expiry:
            _TRANSPORT_PREFERENCE.pop(endpoint.key, None)
            return None
        return transport


def _remember_transport(endpoint: UpstreamEndpoint, transport: str) -> None:
    with _TRANSPORT_PREFERENCE_LOCK:
        _TRANSPORT_PREFERENCE[endpoint.key] = (
            transport,
            time.monotonic() + TRANSPORT_PREFERENCE_TTL_SECONDS,
        )


def send_tcp_query(endpoint: UpstreamEndpoint, payload: bytes, timeout: float) -> bytes:
    last_error: OSError | None = None
    deadline = time.monotonic() + max(0.05, timeout)
    try:
        addresses = _resolve_endpoint(endpoint.host, endpoint.port, socket.SOCK_STREAM)
    except OSError as exc:
        raise OSError(f"Failed to resolve hostname for upstream {endpoint.key}: {exc}") from exc
    for family, socktype, protocol, _canonical_name, address in addresses:
        try:
            with socket.socket(family, socktype, protocol) as sock:
                sock.settimeout(_remaining_timeout(deadline))
                sock.connect(address)
                sock.settimeout(_remaining_timeout(deadline))
                sock.sendall(len(payload).to_bytes(2, "big") + payload)
                sock.settimeout(_remaining_timeout(deadline))
                length = int.from_bytes(_recv_exact(sock, 2), "big")
                if length < 12 or length > MAX_DNS_MESSAGE_BYTES:
                    raise OSError("Upstream TCP response has an invalid DNS length.")
                sock.settimeout(_remaining_timeout(deadline))
                response = _recv_exact(sock, length)
                _validate_upstream_response(payload, response)
                return response
        except OSError as exc:
            last_error = exc
            if time.monotonic() >= deadline:
                break
    if last_error:
        raise last_error
    raise OSError(f"No TCP address found for upstream {endpoint.key}.")


def _send_udp_only(endpoint: UpstreamEndpoint, payload: bytes, timeout: float) -> bytes:
    last_error: OSError | None = None
    deadline = time.monotonic() + max(0.05, timeout)
    try:
        addresses = _resolve_endpoint(endpoint.host, endpoint.port, socket.SOCK_DGRAM)
    except OSError as exc:
        raise OSError(f"Failed to resolve hostname for upstream {endpoint.key}: {exc}") from exc
    for family, socktype, protocol, _canonical_name, address in addresses:
        try:
            with socket.socket(family, socktype, protocol) as sock:
                sock.settimeout(_remaining_timeout(deadline))
                sock.connect(address)
                sock.send(payload)
                response = sock.recv(MAX_DNS_MESSAGE_BYTES)
                _validate_upstream_response(payload, response)
                return response
        except OSError as exc:
            last_error = exc
            if time.monotonic() >= deadline:
                break
    if last_error:
        raise last_error
    raise OSError(f"No UDP address found for upstream {endpoint.key}.")


def send_udp_query(endpoint: UpstreamEndpoint, payload: bytes, timeout: float) -> bytes:
    """Resolve with fast UDP and transparent TCP fallback.

    The public function name is retained for compatibility with existing tests and
    imports, but it now implements transport fallback as required by RFC-compliant
    DNS clients running behind platforms where outbound UDP/53 may be unreliable.
    """
    timeout = max(0.2, float(timeout))
    deadline = time.monotonic() + timeout

    if _transport_preference(endpoint) == "tcp":
        try:
            response = send_tcp_query(endpoint, payload, _remaining_timeout(deadline))
            _remember_transport(endpoint, "tcp")
            return response
        except OSError:
            # The network path may have changed. Give UDP one short recovery try.
            pass

    udp_error: OSError | None = None
    try:
        udp_budget = min(UDP_PROBE_TIMEOUT_SECONDS, _remaining_timeout(deadline))
        response = _send_udp_only(endpoint, payload, udp_budget)
        flags = int.from_bytes(response[2:4], "big")
        if not flags & 0x0200:
            _remember_transport(endpoint, "udp")
            return response
        # TC=1: retry the same DNS message over TCP.
    except OSError as exc:
        udp_error = exc

    try:
        response = send_tcp_query(endpoint, payload, _remaining_timeout(deadline))
        _remember_transport(endpoint, "tcp")
        return response
    except OSError as tcp_error:
        if isinstance(udp_error, (socket.timeout, TimeoutError)) and isinstance(
            tcp_error, (socket.timeout, TimeoutError)
        ):
            raise socket.timeout(
                f"UDP and TCP DNS queries to {endpoint.key} timed out."
            ) from tcp_error
        if udp_error is not None:
            raise OSError(
                f"UDP DNS to {endpoint.key} failed ({udp_error}); "
                f"TCP fallback also failed ({tcp_error})."
            ) from tcp_error
        raise


def query_upstreams_sync(
    payload: bytes,
    profile: ProfileSnapshot,
    runtime: RuntimeState,
    settings: Settings,
) -> bytes:
    endpoints = runtime.ordered_upstreams(profile.upstreams, profile.strategy)
    errors: list[BaseException] = []
    for index, endpoint in enumerate(endpoints):
        started = time.perf_counter()
        try:
            response = send_udp_query(endpoint, payload, settings.upstream_timeout_seconds)
        except (OSError, TimeoutError) as exc:
            errors.append(exc)
            runtime.record_upstream_failure(endpoint, exc, settings)
            continue
        latency_ms = (time.perf_counter() - started) * 1000
        failover = (
            endpoint != profile.upstreams[0]
            if profile.strategy == "primary_failover"
            else index > 0
        )
        runtime.record_upstream_success(endpoint, latency_ms, failover=failover)
        return response
    if errors and all(isinstance(error, (socket.timeout, TimeoutError)) for error in errors):
        raise socket.timeout("All available upstream DNS resolvers timed out.")
    raise OSError("All available upstream DNS resolvers failed.")


async def forward_dns_query(
    payload: bytes,
    profile: ProfileSnapshot,
    runtime: RuntimeState,
    settings: Settings,
) -> bytes:
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None, query_upstreams_sync, payload, profile, runtime, settings
    )


def _decode_dns_name(payload: bytes, offset: int) -> tuple[str, int]:
    """Decode a DNS name and safely support RFC 1035 compression pointers."""
    if offset < 0 or offset >= len(payload):
        raise ValueError("DNS question name is truncated.")

    labels: list[str] = []
    cursor = offset
    end_offset: int | None = None
    visited: set[int] = set()
    jumps = 0
    expanded_length = 1

    while True:
        if cursor >= len(payload):
            raise ValueError("DNS question name is truncated.")
        length = payload[cursor]

        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(payload):
                raise ValueError("DNS compression pointer is truncated.")
            pointer = ((length & 0x3F) << 8) | payload[cursor + 1]
            if pointer >= len(payload):
                raise ValueError("DNS compression pointer is outside the message.")
            if end_offset is None:
                end_offset = cursor + 2
            if pointer in visited or jumps >= MAX_DNS_NAME_POINTER_JUMPS:
                raise ValueError("DNS compression pointer loop detected.")
            visited.add(pointer)
            jumps += 1
            cursor = pointer
            continue

        if length & 0xC0:
            raise ValueError("Unsupported DNS label encoding.")

        cursor += 1
        if length == 0:
            if end_offset is None:
                end_offset = cursor
            break
        if length > 63 or cursor + length > len(payload):
            raise ValueError("DNS question label is invalid.")

        raw_label = payload[cursor : cursor + length]
        try:
            label = raw_label.decode("ascii").lower()
        except UnicodeDecodeError as exc:
            raise ValueError("DNS question label is not ASCII.") from exc
        if not label.isprintable() or "." in label or "\\" in label:
            raise ValueError("DNS question label contains unsupported characters.")
        labels.append(label)
        expanded_length += length + 1
        if expanded_length > 255:
            raise ValueError("DNS question name exceeds 255 bytes.")
        cursor += length

    return ("." if not labels else ".".join(labels)), int(end_offset)


def parse_dns_question(payload: bytes) -> tuple[str, int]:
    if len(payload) < 12:
        raise ValueError("DNS message is shorter than the header.")
    flags = int.from_bytes(payload[2:4], "big")
    opcode = (flags >> 11) & 0x0F
    if opcode != 0:
        raise ValueError(f"Unsupported DNS opcode: {opcode}.")
    question_count = int.from_bytes(payload[4:6], "big")
    if question_count != 1:
        raise ValueError("DNS requests must contain exactly one question.")

    domain, name_end = _decode_dns_name(payload, 12)
    question_end = name_end + 4
    if question_end > len(payload):
        raise ValueError("DNS question type or class is truncated.")
    return domain, question_end


def build_dns_response(
    payload: bytes,
    *,
    rcode: int,
    question_end: int | None,
) -> bytes:
    transaction_id = (payload[:2] + b"\x00\x00")[:2]
    query_flags = int.from_bytes((payload[2:4] + b"\x00\x00")[:2], "big")
    response_flags = 0x8000 | 0x0080 | (query_flags & 0x7900) | (rcode & 0x000F)
    include_question = (
        question_end is not None and len(payload) >= question_end and question_end >= 12
    )
    header = (
        transaction_id
        + response_flags.to_bytes(2, "big")
        + (b"\x00\x01" if include_question else b"\x00\x00")
        + b"\x00\x00\x00\x00\x00\x00"
    )
    return header + (payload[12:question_end] if include_question else b"")


def build_nxdomain_response(payload: bytes, question_end: int) -> bytes:
    return build_dns_response(payload, rcode=3, question_end=question_end)


def build_formerr_response(payload: bytes, question_end: int | None = None) -> bytes:
    return build_dns_response(payload, rcode=1, question_end=question_end)


def build_servfail_response(payload: bytes, question_end: int | None = None) -> bytes:
    return build_dns_response(payload, rcode=2, question_end=question_end)


async def handle_dot(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    settings: Settings,
    runtime: RuntimeState,
    profiles: ProfileStore,
    blocklists: BlocklistManager,
) -> None:
    runtime.connection_delta(1)
    write_lock = asyncio.Lock()
    tasks: set[asyncio.Task] = set()

    async def process_query(payload: bytes) -> None:
        question_end: int | None = None
        blocked = False
        try:
            domain, question_end = parse_dns_question(payload)
            profile = profiles.active()
            blocked = blocklists.domain_is_blocked(domain, profile)
            if blocked:
                response = build_nxdomain_response(payload, question_end)
            else:
                qtype_class = payload[question_end - 4 : question_end]
                response = get_cached_dns_response(
                    profile, domain, qtype_class, payload[:2]
                )
                if response is None:
                    response = await forward_dns_query(payload, profile, runtime, settings)
                    cache_dns_response(
                        profile, domain, qtype_class, response, question_end
                    )
        except ValueError as exc:
            runtime.record_dns_error("malformed_message", str(exc))
            response = build_formerr_response(payload, question_end)
        except Exception as exc:
            safe_error = redact_text(str(exc), settings)
            runtime.record_dns_error(classify_dns_error(exc), safe_error)
            response = build_servfail_response(payload, question_end)

        try:
            async with write_lock:
                writer.write(len(response).to_bytes(2, "big") + response)
                await writer.drain()
            runtime.record_query(blocked=blocked)
        except OSError:
            # A mobile client may abandon the connection while switching between
            # networks/VPN paths. The DNS request itself has already been handled.
            pass

    try:
        while True:
            try:
                header = await asyncio.wait_for(reader.readexactly(2), timeout=60.0)
            except asyncio.TimeoutError:
                break
            except asyncio.IncompleteReadError as exc:
                if exc.partial:
                    runtime.record_unexpected_disconnect()
                break
            length = int.from_bytes(header, "big")
            if not 1 <= length <= MAX_DNS_MESSAGE_BYTES:
                runtime.record_dns_error(
                    "malformed_message", f"Invalid DNS message length: {length}"
                )
                break
            try:
                payload = await asyncio.wait_for(reader.readexactly(length), timeout=5.0)
            except (asyncio.TimeoutError, asyncio.IncompleteReadError) as exc:
                if isinstance(exc, asyncio.IncompleteReadError) and exc.partial:
                    runtime.record_unexpected_disconnect()
                break

            if len(tasks) >= MAX_INFLIGHT_QUERIES_PER_CONNECTION:
                await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            task = asyncio.create_task(process_query(payload))
            tasks.add(task)
            task.add_done_callback(tasks.discard)
    except OSError:
        runtime.record_unexpected_disconnect()
    except Exception as exc:
        runtime.record_dns_error(classify_dns_error(exc), redact_text(str(exc), settings))
    finally:
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        runtime.connection_delta(-1)
        writer.close()
        try:
            await asyncio.wait_for(
                writer.wait_closed(), timeout=DOT_TLS_SHUTDOWN_TIMEOUT_SECONDS
            )
        except OSError:
            # SSL shutdown timeouts are normal when Android or a VPN drops the
            # underlying route without sending TLS close_notify.
            transport = writer.transport
            if transport is not None:
                transport.abort()


async def run_dot_server(
    settings: Settings,
    runtime: RuntimeState,
    profiles: ProfileStore,
    blocklists: BlocklistManager,
    startup_complete: threading.Event,
) -> None:
    from pathlib import Path

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(settings.dot_cert_file, settings.dot_key_file)
    server = await asyncio.start_server(
        lambda reader, writer: handle_dot(
            reader, writer, settings, runtime, profiles, blocklists
        ),
        host=settings.dot_bind_host,
        port=settings.dot_port,
        ssl=context,
        ssl_handshake_timeout=DOT_TLS_HANDSHAKE_TIMEOUT_SECONDS,
        ssl_shutdown_timeout=DOT_TLS_SHUTDOWN_TIMEOUT_SECONDS,
    )
    runtime.update(dot_state="running", dot_last_error=None)
    startup_complete.set()

    async def monitor_certificates() -> None:
        cert_path = Path(settings.dot_cert_file)
        key_path = Path(settings.dot_key_file)
        last_mtime = 0.0
        try:
            if cert_path.exists():
                last_mtime = cert_path.stat().st_mtime
        except OSError:
            pass

        while True:
            await asyncio.sleep(60.0)
            try:
                if cert_path.exists() and key_path.exists():
                    current_mtime = cert_path.stat().st_mtime
                    if current_mtime > last_mtime:
                        certificate = prepare_tls_material(settings)
                        if certificate.valid:
                            context.load_cert_chain(settings.dot_cert_file, settings.dot_key_file)
                            runtime.update(certificate=certificate.as_public())
                            last_mtime = current_mtime
                        else:
                            runtime.update(
                                dot_last_error=f"Attempted cert reload failed: {certificate.error}"
                            )
            except Exception as exc:
                runtime.update(dot_last_error=f"Certificate watcher error: {exc}")

    monitor_task = asyncio.create_task(monitor_certificates())
    try:
        async with server:
            await server.serve_forever()
    finally:
        monitor_task.cancel()


def start_dot_thread(
    settings: Settings,
    runtime: RuntimeState,
    profiles: ProfileStore,
    blocklists: BlocklistManager,
) -> threading.Event:
    startup_complete = threading.Event()
    if not settings.dot_enabled:
        runtime.update(dot_state="disabled", dot_last_error=None)
        startup_complete.set()
        return startup_complete

    runtime.update(dot_state="starting", dot_last_error=None)

    def runner() -> None:
        certificate = prepare_tls_material(settings)
        runtime.update(certificate=certificate.as_public())
        if not certificate.valid:
            runtime.update(dot_state="certificate-error", dot_last_error=certificate.error)
            startup_complete.set()
            return
        try:
            asyncio.run(
                run_dot_server(settings, runtime, profiles, blocklists, startup_complete)
            )
        except Exception as exc:
            safe_error = redact_text(str(exc), settings)
            runtime.update(dot_state="failed", dot_last_error=safe_error)
            startup_complete.set()

    threading.Thread(target=runner, daemon=True).start()
    return startup_complete
