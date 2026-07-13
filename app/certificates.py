from __future__ import annotations

import os
import re
import ssl
import subprocess
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from settings import Settings, _CERTIFICATE_RE, _LABEL_RE, _PRIVATE_KEY_RE


@dataclass(frozen=True)
class CertificateStatus:
    source: str = "missing"
    configured: bool = False
    valid: bool = False
    hostname_match: bool = False
    key_match: bool = False
    expired: bool = False
    not_yet_valid: bool = False
    not_before: str | None = None
    expires_at: str | None = None
    days_remaining: int | None = None
    error: str | None = None

    def as_public(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "configured": self.configured,
            "valid": self.valid,
            "hostname_match": self.hostname_match,
            "key_match": self.key_match,
            "expired": self.expired,
            "not_yet_valid": self.not_yet_valid,
            "not_before": self.not_before,
            "expires_at": self.expires_at,
            "days_remaining": self.days_remaining,
            "error": self.error,
        }


def now_iso(timestamp: float | None = None) -> str:
    value = time.time() if timestamp is None else timestamp
    return datetime.fromtimestamp(value, timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_pem(value: str) -> str:
    normalized = value.replace("\r\n", "\n").replace("\r", "\n").strip()
    if "\n" not in normalized and "\\n" in normalized:
        normalized = normalized.replace("\\n", "\n")
    return normalized + "\n" if normalized else ""


def secure_write(path: Path, content: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        path.parent.chmod(0o700)
    except PermissionError:
        pass
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        path.chmod(mode)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        raise


def valid_dns_hostname(hostname: str) -> bool:
    if not hostname or len(hostname) > 253:
        return False
    try:
        ascii_hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError:
        return False
    labels = ascii_hostname.rstrip(".").split(".")
    return len(labels) >= 2 and all(_LABEL_RE.fullmatch(label) for label in labels)


def dns_pattern_matches(pattern: str, hostname: str) -> bool:
    pattern = pattern.lower().rstrip(".")
    hostname = hostname.lower().rstrip(".")
    if "*" not in pattern:
        return pattern == hostname
    pattern_labels = pattern.split(".")
    hostname_labels = hostname.split(".")
    return (
        pattern_labels[0] == "*"
        and all("*" not in label for label in pattern_labels[1:])
        and len(pattern_labels) == len(hostname_labels)
        and pattern_labels[1:] == hostname_labels[1:]
        and bool(hostname_labels[0])
    )


def _parse_openssl_time(value: str) -> float:
    normalized = " ".join(value.strip().split())
    parsed = datetime.strptime(normalized, "%b %d %H:%M:%S %Y %Z")
    return parsed.replace(tzinfo=timezone.utc).timestamp()


def _openssl_certificate_info(cert_path: Path) -> tuple[list[str], list[str], str, str]:
    command = [
        "openssl", "x509", "-in", str(cert_path), "-noout", "-subject", "-dates",
        "-ext", "subjectAltName",
    ]
    result = subprocess.run(
        command,
        check=True,
        capture_output=True,
        text=True,
        timeout=10,
        env={"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"), "LC_ALL": "C"},
    )
    output = result.stdout
    dns_names = re.findall(r"DNS:([^,\s]+)", output)
    common_names: list[str] = []
    subject_match = re.search(r"(?m)^subject\s*=\s*(.+)$", output)
    if subject_match:
        common_names.extend(
            match.strip()
            for match in re.findall(r"(?:^|[,/])\s*CN\s*=\s*([^,/]+)", subject_match.group(1))
        )
        if not common_names:
            simple = re.search(r"\bCN\s*=\s*([^,]+)", subject_match.group(1))
            if simple:
                common_names.append(simple.group(1).strip())
    not_before_match = re.search(r"(?m)^notBefore=(.+)$", output)
    not_after_match = re.search(r"(?m)^notAfter=(.+)$", output)
    if not not_before_match or not not_after_match:
        raise ValueError("Certificate validity dates were not returned by OpenSSL.")
    return dns_names, common_names, not_before_match.group(1), not_after_match.group(1)


def validate_certificate_files(
    cert_path: Path,
    key_path: Path,
    hostname: str,
    *,
    source: str,
    now: float | None = None,
) -> CertificateStatus:
    current_time = time.time() if now is None else now
    errors: list[str] = []
    key_match = False
    hostname_match = False
    expired = False
    not_yet_valid = False
    not_before_iso: str | None = None
    expires_at_iso: str | None = None
    days_remaining: int | None = None

    if not valid_dns_hostname(hostname):
        errors.append("DOT_PUBLIC_HOSTNAME is missing or is not a valid DNS hostname.")
    if not cert_path.is_file() or not key_path.is_file():
        return CertificateStatus(
            source=source,
            configured=False,
            error="Certificate or private-key file is missing. " + " ".join(errors),
        )

    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(cert_path), str(key_path))
        key_match = True
    except (OSError, ssl.SSLError, ValueError) as exc:
        errors.append(f"Certificate and private key could not be loaded together: {exc}")

    try:
        dns_names, common_names, not_before, not_after = _openssl_certificate_info(cert_path)
        names = dns_names or common_names
        if valid_dns_hostname(hostname):
            hostname_match = any(dns_pattern_matches(name, hostname) for name in names)
            if not hostname_match:
                errors.append(f"Certificate does not match {hostname}.")

        not_before_timestamp = _parse_openssl_time(not_before)
        expiry_timestamp = _parse_openssl_time(not_after)
        not_before_iso = now_iso(not_before_timestamp)
        expires_at_iso = now_iso(expiry_timestamp)
        not_yet_valid = current_time < not_before_timestamp
        expired = current_time >= expiry_timestamp
        days_remaining = max(0, int((expiry_timestamp - current_time) // 86400))
        if not_yet_valid:
            errors.append("Certificate is not valid yet.")
        if expired:
            errors.append("Certificate has expired.")
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        errors.append(f"Certificate could not be decoded: {exc}")

    valid = key_match and hostname_match and not expired and not not_yet_valid and not errors
    return CertificateStatus(
        source=source,
        configured=True,
        valid=valid,
        hostname_match=hostname_match,
        key_match=key_match,
        expired=expired,
        not_yet_valid=not_yet_valid,
        not_before=not_before_iso,
        expires_at=expires_at_iso,
        days_remaining=days_remaining,
        error=" ".join(errors) or None,
    )


def generate_development_certificate(settings: Settings) -> None:
    hostname = settings.dot_public_hostname or "dns-dashboard.local"
    cert_path = Path(settings.dot_cert_file)
    key_path = Path(settings.dot_key_file)
    cert_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30",
            "-subj", f"/CN={hostname}", "-addext", f"subjectAltName=DNS:{hostname}",
            "-keyout", str(key_path), "-out", str(cert_path),
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
    )
    cert_path.chmod(0o600)
    key_path.chmod(0o600)


def prepare_tls_material(settings: Settings, *, now: float | None = None) -> CertificateStatus:
    cert_path = Path(settings.dot_cert_file)
    key_path = Path(settings.dot_key_file)
    has_cert_env = bool(settings.dot_cert_pem.strip())
    has_key_env = bool(settings.dot_key_pem.strip())

    if has_cert_env or has_key_env:
        if not (has_cert_env and has_key_env):
            return CertificateStatus(
                source="environment",
                configured=False,
                error="DOT_CERT_PEM and DOT_KEY_PEM must both be provided.",
            )
        try:
            secure_write(cert_path, normalize_pem(settings.dot_cert_pem))
            secure_write(key_path, normalize_pem(settings.dot_key_pem))
        except OSError as exc:
            return CertificateStatus(
                source="environment",
                configured=False,
                error=f"TLS files could not be written securely: {exc}",
            )
        source = "environment"
    elif settings.production:
        return CertificateStatus(
            source="missing",
            configured=False,
            error="Production requires DOT_CERT_PEM and DOT_KEY_PEM.",
        )
    elif cert_path.exists() and key_path.exists():
        source = "file"
    else:
        try:
            generate_development_certificate(settings)
        except (OSError, subprocess.SubprocessError) as exc:
            return CertificateStatus(
                source="self-signed",
                configured=False,
                error=f"Development certificate generation failed: {exc}",
            )
        source = "self-signed"

    hostname = settings.dot_public_hostname or (
        "dns-dashboard.local" if not settings.production else ""
    )
    return validate_certificate_files(cert_path, key_path, hostname, source=source, now=now)


def redact_text(text: str, settings: Settings) -> str:
    redacted = _PRIVATE_KEY_RE.sub("[REDACTED PRIVATE KEY]", text)
    redacted = _CERTIFICATE_RE.sub("[REDACTED CERTIFICATE]", redacted)
    redacted = re.sub(
        r"(?im)^\s*auth\.token\s*=\s*.*$",
        'auth.token = "[REDACTED]"',
        redacted,
    )
    for secret in (
        settings.frp_auth_token,
        settings.dot_key_pem,
        settings.dot_cert_pem,
        settings.dashboard_password,
    ):
        if not secret:
            continue
        redacted = redacted.replace(secret, "[REDACTED]")
        for line in normalize_pem(secret).splitlines():
            if len(line) >= 16:
                redacted = redacted.replace(line, "[REDACTED]")
    return redacted[:500]
