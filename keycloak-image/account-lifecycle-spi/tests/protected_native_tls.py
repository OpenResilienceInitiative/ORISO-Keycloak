"""Ephemeral, exact-trust native TLS for the owned impersonation fixture only."""

import hashlib
from pathlib import Path
import re
import shutil
import ssl
import subprocess
import tempfile


def cleanup_native_tls(fixture):
    folder = getattr(fixture, "native_tls_folder", None)
    if folder is None:
        return "NOT_STARTED"
    folder = Path(folder)
    if folder.parent.resolve() != Path(tempfile.gettempdir()).resolve() or not re.fullmatch(
        r"oriso-protected-tls-[a-z0-9_]+", folder.name
    ):
        raise AssertionError("Unexpected owned native TLS path")
    if folder.exists():
        shutil.rmtree(folder)
    return "REMOVED_OR_ALREADY_ABSENT"


def prepare_native_tls(fixture):
    folder = Path(tempfile.mkdtemp(prefix="oriso-protected-tls-"))
    fixture.native_tls_folder = folder
    fixture.addClassCleanup(lambda: cleanup_native_tls(fixture))
    certificate, key = folder / "certificate.pem", folder / "private-key.pem"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-sha256",
            "-days", "1", "-nodes", "-subj", "/CN=127.0.0.1",
            "-addext", "subjectAltName=IP:127.0.0.1",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "extendedKeyUsage=serverAuth",
            "-keyout", str(key), "-out", str(certificate),
        ],
        check=True, capture_output=True, timeout=20,
    )
    # The native container runs as uid1000. These one-use synthetic TLS files
    # are mounted read-only; no production identity/key is involved or exported.
    folder.chmod(0o755)
    certificate.chmod(0o644)
    key.chmod(0o644)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cafile=str(certificate))
    assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
    assert len(context.get_ca_certs(binary_form=True)) == 1
    fixture.native_tls_context = context
    fixture.native_tls_certificate_sha256 = hashlib.sha256(
        ssl.PEM_cert_to_DER_cert(certificate.read_text())
    ).hexdigest()


def add_native_tls_arguments(fixture, arguments, image_index):
    arguments[image_index:image_index] = [
        "-p", "127.0.0.1::8443", "-v",
        str(fixture.native_tls_folder) + ":/opt/keycloak/conf/proof-native-tls:ro",
    ]
    arguments.extend([
        "--https-certificate-file=/opt/keycloak/conf/proof-native-tls/certificate.pem",
        "--https-certificate-key-file=/opt/keycloak/conf/proof-native-tls/private-key.pem",
    ])


def refresh_native_tls_endpoint(fixture):
    endpoint = subprocess.run(
        ["docker", "port", fixture.name, "8443/tcp"],
        check=True, capture_output=True, text=True, timeout=30,
    ).stdout.strip()
    if not re.fullmatch(r"127\.0\.0\.1:[1-9][0-9]{0,4}", endpoint):
        raise AssertionError("Unexpected owned native TLS endpoint")
    fixture.native_https_base = "https://" + endpoint
