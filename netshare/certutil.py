"""TLS certificate management: self-signed cert generation and fingerprint pinning.

Server: ensure_cert() creates a self-signed cert via the openssl CLI (present on
virtually every Linux/macOS box) and returns paths + fingerprint.

Client: after TLS connect we hash the peer cert DER (sha256) and compare against
the pinned fingerprint (trust-on-first-use, stored in client state).
"""

import hashlib
import os
import ssl
import subprocess

from .common import log


def _fingerprint_der(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


def fingerprint_of_pem(pem_path: str) -> str:
    der = ssl.PEM_cert_to_DER_cert(open(pem_path).read())
    return _fingerprint_der(der)


def peer_fingerprint(transport: ssl.SSLObject | ssl.SSLSocket) -> str:
    der = transport.getpeercert(binary_form=True)
    return _fingerprint_der(der)


def ensure_cert(cert_dir: str) -> tuple[str, str, str]:
    """Return (cert_path, key_path, sha256_fingerprint), creating cert if needed."""
    os.makedirs(cert_dir, exist_ok=True)
    cert = os.path.join(cert_dir, "server.crt")
    key = os.path.join(cert_dir, "server.key")

    if not (os.path.exists(cert) and os.path.exists(key)):
        log.info("generating self-signed TLS certificate in %s", cert_dir)
        # sync subprocess is fine: happens once, before the event loop matters
        rc = subprocess.call([
            "openssl", "req", "-x509", "-newkey", "ec",
            "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-keyout", key, "-out", cert,
            "-days", "3650", "-nodes",
            "-subj", "/CN=netshare",
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if rc != 0:
            raise RuntimeError(
                "openssl failed to generate a certificate; install openssl "
                "or place server.crt/server.key in " + cert_dir
            )
        os.chmod(key, 0o600)

    return cert, key, fingerprint_of_pem(cert)


def server_ssl_context(cert: str, key: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cert, key)
    return ctx


def client_ssl_context() -> ssl.SSLContext:
    """No CA verification: authenticity is enforced by fingerprint pinning."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx
