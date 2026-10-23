#!/usr/bin/env python3
"""Finite proof of providers installed in the actual image, with no JAR mounts."""

import argparse
import base64
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
import zipfile

ROOT = Path(__file__).resolve().parents[2]
SUPPORT = ROOT / "keycloak-image/account-lifecycle-spi/tests"
sys.path.insert(0, str(SUPPORT))
from lifecycle_fixture import call
from run_native import XmlResult

REALM = "scenario-c-installed-image"
PASSWORD = "synthetic-installed-image-password-0001"
SUBJECTS = {
    name: str(uuid.uuid5(uuid.NAMESPACE_URL, "oriso-image-proof/" + name))
    for name in ("CREATE", "ADMIN", "MAIL")
}
PROVIDERS = {
    "otp": (
        "de.onlineberatung.RealmOtpResourceProviderFactory",
        "keycloak-otp-config-spi-1.0-SNAPSHOT-keycloak.jar",
    ),
    "smtp": (
        "org.oriso.keycloak.smtp.SmtpControlFactory",
        "smtp-control-spi-1.0-SNAPSHOT.jar",
    ),
    "lifecycle": (
        "org.oriso.keycloak.lifecycle.AccountLifecycleFactory",
        "account-lifecycle-spi-1.0-SNAPSHOT.jar",
    ),
}


def docker(*args, **kwargs):
    return subprocess.run(
        ["docker", *args], check=True, capture_output=True, text=True, **kwargs
    )


def installed_key_guard_names(text):
    """Export fixed provider guard names, never raw startup logs or arbitrary exit credit."""
    guards = {
        "LIFECYCLE": "Lifecycle key must contain at least 32 bytes",
        "SMTP": "SMTP context key must contain at least 32 bytes",
        "PROTECTED": "Invalid protected context key",
        "SESSION": "Invalid session key length",
    }
    found = set()
    for line in text.splitlines():
        value = line.strip()
        if value.startswith("ERROR: "):
            value = value.removeprefix("ERROR: ")
        if "java.lang.IllegalStateException: " in value:
            value = value.rsplit("java.lang.IllegalStateException: ", 1)[1]
        for name, message in guards.items():
            if value == message:
                found.add(name)
    return sorted(found)


def source_manifest():
    paths = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, check=True, capture_output=True
    ).stdout.decode().split("\0")
    return {
        name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        for name in paths
        if name and (ROOT / name).is_file()
    }


class InstalledImage(unittest.TestCase):
    image = None
    run_id = None
    receipt = {}

    @contextmanager
    def container(self, enabled=False, invalid_key=False):
        name = "oriso-c-image-" + uuid.uuid4().hex[:12]
        command = [
            "run", "-d", "--name", name,
            "--label", "oriso-c-image-proof-run=" + self.run_id,
            "--memory", "1536m", "--cpus", "2",
            "-p", "127.0.0.1::8080",
            "-e", "JAVA_OPTS_APPEND=-Xms128m -Xmx512m -XX:ActiveProcessorCount=2",
            "-e", "KC_BOOTSTRAP_ADMIN_USERNAME=synthetic-installer",
            "-e", "KC_BOOTSTRAP_ADMIN_PASSWORD=" + PASSWORD,
            "-e", "ORISO_APP_BASE_URL=https://image-proof.internal",
            "-e", "EMAIL_BRANDING_NAME=Installed Image Fixture",
            "-e", "EMAIL_LEGAL_ORGANISATION_NAME=Fixture Operator",
        ]
        if enabled:
            env = {
                "TASK_IDENTITY_MODEL": "FIVE_ACTORS",
                "IDENTITY_ACCOUNT_ADMIN_CLIENT_ID": "backend-account-admin",
                "IDENTITY_ACCOUNT_CREATE_SERVICE_SUBJECT": SUBJECTS["CREATE"],
                "IDENTITY_ACCOUNT_ADMIN_SERVICE_SUBJECT": SUBJECTS["ADMIN"],
                "IDENTITY_MAIL_SERVICE_SUBJECT": SUBJECTS["MAIL"],
                "ORISO_TASK_CONTEXT_KEY": base64.b64encode(
                    b"x" if invalid_key else bytes(range(32))
                ).decode(),
                "ORISO_ACCOUNT_LIFECYCLE_ENABLED": "true",
                "ORISO_ACCOUNT_LIFECYCLE_REALM": REALM,
                "ORISO_ACCOUNT_LIFECYCLE_GROUPS": '{"/human-roles/user":["user"]}',
                "ORISO_IDENTITY_DUMMY_EMAIL_SUFFIX": "@image-proof.invalid",
                "ORISO_SMTP_CONTROL_ENABLED": "true",
                "ORISO_SMTP_CONTROL_REALM": REALM,
            }
            for key, value in env.items():
                command.extend(["-e", key + "=" + value])
        docker(*command, self.image, "start-dev")
        try:
            info = json.loads(docker("inspect", name).stdout)[0]
            self.assertEqual([], info["Mounts"], "Image proof cannot mount providers")
            self.assertEqual(self.image, info["Image"])
            address = docker("port", name, "8080/tcp").stdout.strip().splitlines()[0]
            self.assertRegex(address, r"^127\.0\.0\.1:\d+$")
            yield name, "http://" + address
        finally:
            docker("rm", "-fv", name)

    def await_start(self, name, base):
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            state = json.loads(docker("inspect", name).stdout)[0]["State"]
            if not state["Running"]:
                return False, None
            try:
                status, body = call(
                    base, "POST", "/realms/master/protocol/openid-connect/token",
                    {"client_id": "admin-cli", "grant_type": "password",
                     "username": "synthetic-installer", "password": PASSWORD},
                    form=True,
                )
                if status == 200:
                    self.assertIsInstance(body.get("access_token"), str)
                    return True, body["access_token"]
            except (OSError, TimeoutError):
                pass
            time.sleep(1)
        self.fail("Installed image reached neither readiness nor an explicit exit")

    def realm(self, name, base):
        ready, token = self.await_start(name, base)
        self.assertTrue(ready, "Installed image did not start")
        status, _ = call(
            base, "POST", "/admin/realms",
            {"id": REALM, "realm": REALM, "enabled": True}, token=token,
        )
        self.assertEqual(201, status)

    def test_exact_installed_provider_inventory_and_service_descriptors(self):
        name = "oriso-c-image-inventory-" + uuid.uuid4().hex[:12]
        docker("create", "--name", name,
               "--label", "oriso-c-image-proof-run=" + self.run_id, self.image)
        try:
            with tempfile.TemporaryDirectory(prefix="oriso-installed-providers-") as tmp:
                docker("cp", name + ":/opt/keycloak/providers/.", tmp)
                jars = sorted(Path(tmp).glob("*.jar"))
                self.assertEqual(
                    sorted(item[1] for item in PROVIDERS.values()),
                    [p.name for p in jars],
                    "Production image must contain exactly the three bounded providers",
                )
                hashes = {}
                descriptor = "META-INF/services/org.keycloak.services.resource.RealmResourceProviderFactory"
                for kind, (factory, filename) in PROVIDERS.items():
                    jar = Path(tmp) / filename
                    with zipfile.ZipFile(jar) as archive:
                        factories = archive.read(descriptor).decode().splitlines()
                        self.assertIn(factory, factories)
                        self.assertIn(factory.replace(".", "/") + ".class", archive.namelist())
                        if kind != "otp":
                            self.assertIn(
                                "META-INF/services/org.keycloak.connections.jpa.entityprovider.JpaEntityProviderFactory",
                                archive.namelist(),
                            )
                    hashes[filename] = hashlib.sha256(jar.read_bytes()).hexdigest()
                self.receipt["installedJarSha256"] = hashes
        finally:
            docker("rm", "-fv", name)

    def test_default_off_image_preserves_otp_and_denies_bounded_commands(self):
        with self.container() as (name, base):
            self.realm(name, base)
            routes = [
                ("GET", "/otp-config/fetch-otp-setup-info/unowned", 401),
                ("GET", "/oriso-smtp-control/v1/smtp", 403),
                ("PUT", "/oriso-account-lifecycle/v1/attempts/" + str(uuid.uuid4()), 404),
            ]
            for method, route, expected in routes:
                with self.subTest(route=route.split("/")[1]):
                    status, _ = call(base, method, "/realms/" + REALM + route,
                                     body={} if method == "PUT" else None)
                    self.assertEqual(expected, status)

    def test_enabled_image_exposes_both_bounded_providers_with_no_anonymous_power(self):
        with self.container(enabled=True) as (name, base):
            self.realm(name, base)
            for method, route in (
                ("GET", "/oriso-smtp-control/v1/smtp"),
                ("PUT", "/oriso-account-lifecycle/v1/attempts/" + str(uuid.uuid4())),
            ):
                with self.subTest(route=route.split("/")[1]):
                    status, _ = call(base, method, "/realms/" + REALM + route,
                                     body={} if method == "PUT" else None)
                    self.assertEqual(401, status)

    def test_installed_modules_refuse_invalid_shared_key_at_startup(self):
        with self.container(enabled=True, invalid_key=True) as (name, base):
            ready, _ = self.await_start(name, base)
            self.assertFalse(ready, "Installed providers accepted a one-byte context key")
            state = json.loads(docker("inspect", name).stdout)[0]["State"]
            self.assertFalse(state["Running"])
            self.assertNotEqual(0, state["ExitCode"])
            logs = docker("logs", name)
            text = logs.stdout + logs.stderr
            guards = installed_key_guard_names(text)
            type(self).receipt["invalidKeyStartup"] = {
                "readinessRefused": ready is False,
                "containerExited": state["Running"] is False,
                "nonzeroExitVerified": state["ExitCode"] != 0,
                "guardNames": guards,
            }
            self.assertTrue(guards, "Failure must come from the installed provider key guard")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("image")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", args.image):
        raise SystemExit("An immutable local image ID is required")
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, check=True,
        capture_output=True, text=True,
    ).stdout.strip()
    image = json.loads(docker("image", "inspect", args.image).stdout)[0]
    if image["Id"] != args.image or image["Config"].get("Labels", {}).get(
        "org.opencontainers.image.revision"
    ) != head:
        raise SystemExit("Image ID and source revision label must match this checkout")
    InstalledImage.image, InstalledImage.run_id = args.image, uuid.uuid4().hex
    before = source_manifest()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(InstalledImage)
    if suite.countTestCases() != 4:
        raise SystemExit("Installed image case inventory must contain exactly four cases")
    result = unittest.TextTestRunner(verbosity=2, resultclass=XmlResult).run(suite)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    result.write_xml(args.report.with_suffix(".xml"), "installed-image")
    after = source_manifest()
    report = {
        "commit": head, "imageId": args.image, "runId": InstalledImage.run_id,
        "tests": result.testsRun, "failures": len(result.failures),
        "errors": len(result.errors), "skipped": len(result.skipped),
        "sourceBefore": before, "sourceAfter": after,
        "installed": InstalledImage.receipt,
        "scope": "installed image inventory, default-off, native routes and invalid startup only; not full Scenario C",
    }
    report["accepted"] = (
        result.wasSuccessful() and result.testsRun == 4 and not result.skipped
        and before == after and len(InstalledImage.receipt.get("installedJarSha256", {})) == 3
    )
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k not in ("sourceBefore", "sourceAfter")}, sort_keys=True))
    return not report["accepted"]


if __name__ == "__main__":
    raise SystemExit(main())
