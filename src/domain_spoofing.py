#!/usr/bin/env python3
"""
Domain Spoofing for the Verifier (Phase 2)
==================================================

71.3% of the true-positive vulnerabilities in the thesis dataset are domain-restricted: they can
only be triggered from a specific origin (enforced by a manifest match and/or a runtime origin
check in the extension's code). The baseline verifier always navigates to ``http://example.com``,
so any *code-based* origin check fails and the payload never fires — this is the primary reason the
request categories verified at only 1.6% / 3.3%.

This module lets the verifier load the attacker page under the **real** restricted origin:

  1. A self-signed wildcard certificate is generated once (Chrome is launched with
     ``--ignore-certificate-errors`` so the cert is never actually validated).
  2. A tiny local HTTPS server answers for any host/path with a minimal HTML document, so
     ``DOMContentLoaded`` fires and content scripts / the verifier extension execute.
  3. Chrome is launched with ``--host-resolver-rules="MAP <domain> 127.0.0.1:<port>"`` so requests
     for the restricted domain resolve to that local server, while ``127.0.0.1`` (the mock server
     used by payloads) is left untouched.
  4. The verifier navigates to ``https://<specific_domain>/`` — from Chrome's perspective the page
     origin now equals the restricted domain, satisfying code-based origin checks.

Everything here is inert unless ``config.ENABLE_DOMAIN_SPOOFING`` is True.
"""

from __future__ import annotations

import datetime
import ipaddress
import os
import tempfile
import threading
from pathlib import Path
from typing import List, Optional, Tuple

# ---------------------------------------------------------------------------
# Certificate generation
# ---------------------------------------------------------------------------

def _default_cert_dir() -> Path:
    """Pick a writable directory for the cached spoof cert.

    Never the source tree: under Docker ``/app/src`` is root-owned while the verifier runs as a
    non-root user, so writing there fails with EPERM. Preference order: an explicit override, the
    (mounted, persistent) verification output dir, then the system temp dir as a last resort.
    """
    candidates: List[Path] = []
    override = os.getenv("SPOOF_CERT_DIR")
    if override:
        candidates.append(Path(override))
    # Imported lazily: this module is otherwise config-free (spoof_target takes config as an arg).
    try:
        import config as _config
        results_dir = getattr(_config, "RESULTS_VERIFICATION_DIR", None)
        if results_dir:
            candidates.append(Path(results_dir) / ".spoof_certs")
    except Exception:  # noqa: BLE001 - config is optional here
        pass
    candidates.append(Path(tempfile.gettempdir()) / "verifier_spoof_certs")

    for cand in candidates:
        try:
            cand.mkdir(parents=True, exist_ok=True)
            probe = cand / ".write_test"
            probe.write_text("ok", encoding="utf-8")
            probe.unlink()
            return cand
        except Exception:  # noqa: BLE001 - try the next candidate
            continue
    # Every candidate failed; return the temp path anyway so the caller raises a clear error.
    return Path(tempfile.gettempdir()) / "verifier_spoof_certs"


def generate_self_signed_cert(cert_dir: Path) -> Tuple[Path, Path]:
    """Generate (once) a self-signed wildcard cert + key, returning their paths.

    The cert is only needed so the local TLS server can start; Chrome is launched with
    ``--ignore-certificate-errors`` and never validates it. Cached on disk between runs.
    """
    cert_dir.mkdir(parents=True, exist_ok=True)
    cert_path = cert_dir / "spoof_cert.pem"
    key_path = cert_dir / "spoof_key.pem"

    if cert_path.exists() and key_path.exists():
        return cert_path, key_path

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "verifier-spoof")])
    san = x509.SubjectAlternativeName([
        x509.DNSName("*"),
        x509.DNSName("*.*"),
        x509.DNSName("*.*.*"),
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
    ])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(san, critical=False)
        .sign(key, hashes.SHA256())
    )

    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


# ---------------------------------------------------------------------------
# Local HTTPS "origin" server
# ---------------------------------------------------------------------------

_MINIMAL_PAGE = (
    "<!doctype html><html><head><meta charset='utf-8'>"
    "<title>verifier</title></head><body><h1>verifier</h1></body></html>"
)


class DomainSpoofServer:
    """A minimal HTTPS server that answers for ANY host/path with a small HTML document.

    Requests for the spoofed domain are routed here by Chrome's ``--host-resolver-rules``.
    """

    def __init__(self, host: str = "127.0.0.1", https_port: int = 3443):
        self.host = host
        self.https_port = https_port
        self.thread: Optional[threading.Thread] = None
        self.is_running = False

    def start(self) -> bool:
        if self.is_running:
            return True

        from flask import Flask, Response
        import logging as _logging
        _logging.getLogger("werkzeug").setLevel(_logging.ERROR)

        app = Flask("domain_spoof")

        @app.route("/", defaults={"_path": ""}, methods=["GET", "POST", "OPTIONS"])
        @app.route("/<path:_path>", methods=["GET", "POST", "OPTIONS"])
        def _catch_all(_path):
            return Response(_MINIMAL_PAGE, mimetype="text/html", status=200)

        cert_dir = _default_cert_dir()
        cert_path, key_path = generate_self_signed_cert(cert_dir)

        def _run():
            app.run(
                host=self.host,
                port=self.https_port,
                debug=False,
                use_reloader=False,
                ssl_context=(str(cert_path), str(key_path)),
            )

        self.thread = threading.Thread(target=_run, daemon=True)
        self.thread.start()

        import time
        time.sleep(1.0)
        self.is_running = True
        print(f"[HTTPS] Domain-spoof origin server on https://{self.host}:{self.https_port}")
        return True

    def stop(self) -> bool:
        # Daemon thread; terminates with the process.
        self.is_running = False
        return True


_spoof_instance: Optional[DomainSpoofServer] = None


def get_spoof_server(host: str = "127.0.0.1", https_port: int = 3443) -> DomainSpoofServer:
    global _spoof_instance
    if _spoof_instance is None:
        _spoof_instance = DomainSpoofServer(host, https_port)
    return _spoof_instance


# ---------------------------------------------------------------------------
# Chrome launch args + navigation URL
# ---------------------------------------------------------------------------

def _normalize_domain(specific_domain: Optional[str]) -> Optional[str]:
    """Strip scheme / www / path / port from a stored specific_domain, returning the bare host."""
    if not specific_domain or not isinstance(specific_domain, str):
        return None
    d = specific_domain.strip().lower()
    for prefix in ("https://", "http://", "*://"):
        if d.startswith(prefix):
            d = d[len(prefix):]
    # Drop path/query/fragment, a leading wildcard label, and any :port suffix.
    d = d.split("/")[0].split("?")[0].split("#")[0]
    if d.startswith("*."):
        d = d[2:]
    if d.startswith("www."):
        d = d[4:]
    # Strip a trailing :port (but keep bracketed IPv6 intact — those are rejected below anyway).
    if ":" in d and not d.startswith("["):
        d = d.split(":")[0]
    return d or None


def _is_spoofable(domain: Optional[str]) -> bool:
    """True only for a real, public-style hostname we can safely MAP to the local origin server.

    Refuses empty / localhost / bare IPs / host-less names. Spoofing any of these would either
    collide with the mock server (127.0.0.1:3000) or the loopback the payloads target, silently
    breaking request detection — so instead we fall back to the default navigation.
    """
    if not domain:
        return False
    if domain == "localhost" or domain.endswith(".localhost"):
        return False
    # Bare IPv4/IPv6 literal — never spoof (would fight host-resolver rules / the mock server).
    try:
        ipaddress.ip_address(domain)
        return False
    except ValueError:
        pass
    # Must look like a real hostname with a TLD (e.g. "example.com"), not a single label.
    if "." not in domain:
        return False
    # Reject anything with characters a hostname can't contain (defensive against junk fields).
    if any(c.isspace() for c in domain) or "," in domain:
        return False
    return True


def chrome_args_for_domain(domain: str, https_port: int) -> List[str]:
    """Build the ``--host-resolver-rules`` + cert-ignore args mapping ``domain`` to the local server.

    Maps both the bare domain and its subdomains; leaves 127.0.0.1 (the mock server) untouched.
    """
    mapping = f"MAP {domain} 127.0.0.1:{https_port}, MAP *.{domain} 127.0.0.1:{https_port}"
    return [
        f"--host-resolver-rules={mapping}",
        "--ignore-certificate-errors",
        # The spoofed origin is HTTPS but the payload fetches the HTTP mock server (127.0.0.1:3000);
        # that is mixed active content Chrome blocks by default. Without this flag every spoofed
        # request/code_execution test would silently fail (no request reaches the mock server).
        "--allow-running-insecure-content",
    ]


def _is_direct_runtime_only(payload: Optional[str]) -> bool:
    """True when the payload reaches the extension only via chrome.runtime messaging
    (``sendMessage`` / ``connect``) and not via a page-DOM channel (``postMessage`` /
    ``dispatchEvent``).

    Such payloads depend on ``externally_connectable``, which is set to the default origin
    (example.com). Spoofing navigates the page to the restricted origin, which Chrome then rejects for
    ``externally_connectable``, silently breaking the message — measured to cost 88 verified storage
    exploits for a 16-exploit gain when spoofing was applied globally. They already work on the default
    origin, so they must not be spoofed. Page-DOM payloads, by contrast, need the real origin to pass a
    content script's ``event.origin`` check, so those are still spoofed.
    """
    p = payload or ""
    page_dom = ("postMessage" in p) or ("dispatchEvent" in p) or ("CustomEvent" in p)
    direct = ("sendMessage" in p) or (".connect(" in p)
    return direct and not page_dom


def spoof_target(vuln: dict, config) -> Tuple[str, List[str]]:
    """Resolve (navigation_url, extra_launch_args) for a vulnerability.

    When domain spoofing is disabled or the vulnerability has no specific_domain, this is a no-op
    that returns the configured default navigation URL (``config.VERIFICATION_PAGE_URL`` — the
    localhost/example.com toggle) with no extra args, so existing behavior is preserved.
    """
    default_url = getattr(config, "VERIFICATION_PAGE_URL", "http://example.com")
    default = (default_url, [])
    if not getattr(config, "ENABLE_DOMAIN_SPOOFING", False):
        return default

    # Never spoof a direct-runtime-only payload: navigating off the externally_connectable origin
    # would break it. It already works on the default origin.
    if _is_direct_runtime_only(vuln.get("attacker_payload")):
        return default

    details = vuln.get("verification_details") or {}
    domain = _normalize_domain(details.get("specific_domain"))
    # Fall back to the default navigation when there's no domain, or the "domain" is something we
    # must not spoof (localhost / an IP / the mock host) — see _is_spoofable. This keeps spoofing
    # from silently breaking loopback request detection and avoids false negatives.
    if not _is_spoofable(domain):
        return default

    # Never let a spoof rule capture the mock-server host itself.
    mock_host = str(getattr(config, "MOCK_SERVER_HOST", "127.0.0.1")).strip().lower()
    if domain == mock_host or domain.endswith("." + mock_host):
        return default

    https_port = getattr(config, "DOMAIN_SPOOF_HTTPS_PORT", 3443)
    # Navigate to the normalized restricted host over HTTPS; from Chrome's perspective the page
    # origin now equals the restricted domain, satisfying code-based origin checks.
    nav_url = f"https://{domain}/"
    return nav_url, chrome_args_for_domain(domain, https_port)
