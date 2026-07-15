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
RESOLVER_CACHE_TTL = 300.0  # 5 minutes


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
        if cache_key in _RESOLVER_CACHE:
            cached_addrs, expiry = _RESOLVER_CACHE[cache_key]
            if now < expiry:
                return cached_addrs

    try:
        addresses = socket.getaddrinfo(host, port, type=socktype)
        # Prioritize IPv4 to minimize timeouts on IPv6-unfriendly networks
        addresses = sorted(addresses, key=lambda addr: 0 if addr[0] == socket.AF_INET else 1)
    except OSError as exc:
        with _RESOLVER_CACHE_LOCK:
            if cache_key in _RESOLVER_CACHE:
                return _RESOLVER_CACHE[cache_key][0]
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


def send_tcp_query(endpoint: UpstreamEndpoint, payload: bytes, timeout: float) -> bytes:
    last_error: OSError | None = None
    try:
        addresses = _resolve_endpoint(endpoint.host, endpoint.port, socket.SOCK_STREAM)
    except OSError as exc:
        raise OSError(f"Failed to resolve hostname for upstream {endpoint.key}: {exc}") from exc
    for family, socktype, protocol, _canonical_name, address in addresses:
        try:
            with socket.socket(family, socktype, protocol) as sock:
                sock.settimeout(timeout)
                sock.connect(address)
                sock.sendall(len(payload).to_bytes(2, "big") + payload)
                length = int.from_bytes(_recv_exact(sock, 2), "big")
                if length < 12 or length > MAX_DNS_MESSAGE_BYTES:
                    raise OSError("Upstream TCP response has an invalid DNS length.")
                response = _recv_exact(sock, length)
                _validate_upstream_response(payload, response)
                return response
        except OSError as exc:
            last_error = exc
    if last_error:
        raise last_error
    raise OSError(f"No TCP address found for upstream {endpoint.key}.")


def send_udp_query(endpoint: UpstreamEndpoint, payload: bytes, timeout: float) -> bytes:
    last_error: OSError | None = None
    try:
        addresses = _resolve_endpoint(endpoint.host, endpoint.port, socket.SOCK_DGRAM)
    except OSError as exc:
        raise OSError(f"Failed to resolve hostname for upstream {endpoint.key}: {exc}") from exc
    for family, socktype, protocol, _canonical_name, address in addresses:
        try:
            with socket.socket(family, socktype, protocol) as sock:
                sock.settimeout(timeout)
                sock.connect(address)
                sock.send(payload)
                response = sock.recv(MAX_DNS_MESSAGE_BYTES)
                _validate_upstream_response(payload, response)
                flags = int.from_bytes(response[2:4], "big")
                if flags & 0x0200:
                    return send_tcp_query(endpoint, payload, timeout)
                return response
        except OSError as exc:
            last_error = exc
    if last_error:
        raise last_error
    raise OSError(f"No UDP address found for upstream {endpoint.key}.")


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


def parse_dns_question(payload: bytes) -> tuple[str, int]:
    if len(payload) < 12:
        raise ValueError("DNS message is shorter than the header.")
    question_count = int.from_bytes(payload[4:6], "big")
    if question_count != 1:
        raise ValueError("DNS requests must contain exactly one question.")
    offset = 12
    labels: list[str] = []
    while True:
        if offset >= len(payload):
            raise ValueError("DNS question name is truncated.")
        length = payload[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0:
            raise ValueError("Compressed DNS question names are not accepted in requests.")
        if length > 63 or offset + length > len(payload):
            raise ValueError("DNS question label is invalid.")
        try:
            label = payload[offset : offset + length].decode("ascii").lower()
        except UnicodeDecodeError as exc:
            raise ValueError("DNS question label is not ASCII.") from exc
        if not label.isprintable() or "." in label or "\\" in label:
            raise ValueError("DNS question label contains unsupported characters.")
        labels.append(label)
        offset += length
    if offset + 4 > len(payload):
        raise ValueError("DNS question type or class is truncated.")
    domain = "." if not labels else ".".join(labels)
    return domain, offset + 4


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
                response = await forward_dns_query(payload, profile, runtime, settings)
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
        except (ConnectionError, ssl.SSLError):
            pass

    try:
        while True:
            try:
                # Set a 60-second idle timeout on reading the next DNS query header
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
                # Set a 5-second timeout on reading the packet payload
                payload = await asyncio.wait_for(reader.readexactly(length), timeout=5.0)
            except (asyncio.TimeoutError, asyncio.IncompleteReadError) as exc:
                if isinstance(exc, asyncio.IncompleteReadError) and exc.partial:
                    runtime.record_unexpected_disconnect()
                break

            task = asyncio.create_task(process_query(payload))
            tasks.add(task)
            task.add_done_callback(tasks.discard)
    except (ConnectionResetError, BrokenPipeError, ssl.SSLError, ConnectionError):
        runtime.record_unexpected_disconnect()
    except Exception as exc:
        runtime.record_dns_error(classify_dns_error(exc), redact_text(str(exc), settings))
    finally:
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        runtime.connection_delta(-1)
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, ssl.SSLError):
            pass


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
    )
    runtime.update(dot_state="running", dot_last_error=None)
    startup_complete.set()

    # Background task to monitor certificate file changes and reload hot
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
            await asyncio.sleep(60.0)  # Check every 60 seconds
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
                            runtime.update(dot_last_error=f"Attempted cert reload failed: {certificate.error}")
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
