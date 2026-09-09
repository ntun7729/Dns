from __future__ import annotations

import os
from pathlib import Path

from certificates import normalize_pem, secure_write, validate_certificate_files
from settings import Settings


def install_tls_material(settings: Settings, certificate_pem: str, private_key_pem: str):
    """Validate a candidate certificate/key pair before replacing the active files."""
    certificate = normalize_pem(certificate_pem)
    private_key = normalize_pem(private_key_pem)
    if not certificate or not private_key:
        raise ValueError("Certificate and private key must both be provided.")
    if len(certificate.encode("utf-8")) > 1024 * 1024:
        raise ValueError("Certificate payload is too large.")
    if len(private_key.encode("utf-8")) > 1024 * 1024:
        raise ValueError("Private-key payload is too large.")

    cert_path = Path(settings.dot_cert_file)
    key_path = Path(settings.dot_key_file)
    cert_candidate = cert_path.with_name(f".{cert_path.name}.candidate")
    key_candidate = key_path.with_name(f".{key_path.name}.candidate")
    secure_write(cert_candidate, certificate, mode=0o600)
    secure_write(key_candidate, private_key, mode=0o600)
    try:
        status = validate_certificate_files(
            cert_candidate,
            key_candidate,
            settings.dot_public_hostname,
            source="dashboard",
        )
        if not status.valid:
            raise ValueError(status.error or "TLS certificate validation failed.")
        cert_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.replace(cert_candidate, cert_path)
        os.replace(key_candidate, key_path)
        cert_path.chmod(0o600)
        key_path.chmod(0o600)
        return validate_certificate_files(
            cert_path,
            key_path,
            settings.dot_public_hostname,
            source="dashboard",
        )
    finally:
        cert_candidate.unlink(missing_ok=True)
        key_candidate.unlink(missing_ok=True)
