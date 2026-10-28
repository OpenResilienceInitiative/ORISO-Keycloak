#!/usr/bin/env python3
"""Finite proof of providers installed in the actual image, with no JAR mounts."""

import argparse
import base64
import copy
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
from installed_key_guards import installed_key_guard_names

REALM = "scenario-c-installed-image"
PASSWORD = "synthetic-installed-image-password-0001"
SUBJECTS = {
    name: str(uuid.uuid5(uuid.NAMESPACE_URL, "oriso-image-proof/" + name))
    for name in ("CREATE", "ADMIN", "SETUP")
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
                "IDENTITY_SETUP_SERVICE_SUBJECT": SUBJECTS["SETUP"],
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

    def test_operator_scripts_preserve_current_and_migrate_legacy_magic_link_flow(self):
        source = json.loads((ROOT / "realm.json").read_text())
        aliases = ("direct-grant-2fa", "oriso-ordinary-password", "app-otp-conditional", "email-otp-conditional")
        expected = {f["alias"]: [(e.get("authenticator", e.get("flowAlias")), e["requirement"], e["priority"])
                    for e in sorted(f["authenticationExecutions"], key=lambda e: e["priority"])]
                    for f in source["authenticationFlows"] if f["alias"] in aliases}
        observations = {}
        with self.container() as (name, base):
            ready, token = self.await_start(name, base)
            self.assertTrue(ready, "Operator proof requires the actual installed image")
            docker("exec", "-i", name, "bash", "-s", input=
                "/opt/keycloak/bin/kcadm.sh config credentials --server http://localhost:8080 "
                "--realm master --user synthetic-installer --password " + PASSWORD + "\n")
            for variant in ("current", "legacy"):
                realm = REALM + "-operator-" + variant
                flows = copy.deepcopy(source["authenticationFlows"])
                configs = copy.deepcopy(source["authenticatorConfig"])
                for item in flows + configs: item.pop("id", None)
                if variant == "legacy":
                    flows = [f for f in flows if f["alias"] != "oriso-ordinary-password"]
                    direct = next(f for f in flows if f["alias"] == "direct-grant-2fa")
                    direct["authenticationExecutions"] = [
                        {"authenticator": provider, "authenticatorFlow": False,
                         "requirement": "REQUIRED", "priority": priority}
                        for priority, provider in [(10, "direct-grant-validate-username"), (20, "direct-grant-validate-password")]
                    ] + [e for e in direct["authenticationExecutions"]
                         if e.get("flowAlias") in ("app-otp-conditional", "email-otp-conditional")]
                status, _ = call(base, "POST", "/admin/realms", {
                    "realm": realm, "enabled": True, "authenticationFlows": flows,
                    "authenticatorConfig": configs, "directGrantFlow": "direct-grant-2fa",
                    "browserFlow": source["browserFlow"], "emailTheme": source["emailTheme"]}, token=token)
                self.assertEqual(201, status)

                def read(path):
                    status, body = call(base, "GET", "/admin/realms/" + realm + path, token=token)
                    self.assertEqual(200, status, "Operator native read must succeed")
                    return body

                def snapshot():
                    value = {}
                    for alias in aliases:
                        if variant == "legacy" and alias == "oriso-ordinary-password" and not migrated:
                            continue
                        entries = read("/authentication/flows/" + alias + "/executions")
                        value[alias] = [e for e in entries if e.get("level", 0) == 0]
                    return value

                def contract(value):
                    return {a: [(e.get("providerId", e.get("displayName")), e["requirement"], e["priority"])
                                for e in entries] for a, entries in value.items()}

                migrated = False
                before = snapshot()
                config_id = next(e["authenticationConfig"] for e in before["email-otp-conditional"]
                                 if e.get("providerId") == "email-authenticator")
                config_before = read("/authentication/config/" + config_id)
                protected_ids = {e["id"] for a, entries in before.items() for e in entries
                                 if variant == "current" or a in ("app-otp-conditional", "email-otp-conditional")}
                first = None
                for _ in range(2):
                    docker("exec", "-i", "-e", "REALM=" + realm, name, "bash", "-s",
                           input=(ROOT / "scripts/keycloak-apply-2fa-flow.sh").read_text())
                    migrated = True
                    docker("exec", "-e", "REALM=" + realm, name,
                           "/opt/keycloak/bin/oriso-verify-2fa-flow.sh")
                    after = snapshot()
                    self.assertTrue(contract(after) == expected, "Actual operator flow must match the shipped realm exactly")
                    self.assertTrue(protected_ids.issubset({e["id"] for entries in after.values() for e in entries}),
                                    "Current Magic Link and OTP execution identities must survive")
                    self.assertTrue(read("/authentication/config/" + config_id) == config_before,
                                    "Original OTP configuration must survive")
                    if first is not None:
                        self.assertTrue(after == first, "Second apply must preserve all execution identities and settings")
                    first = after
                observations[variant] = {"exactRealmContract": True, "protectedExecutionIdsPreserved": True,
                    "otpConfigurationPreserved": True, "secondApplyIdentical": True, "shippedVerifierPassed": True,
                    "applyRuns": 2}
        self.receipt["operatorFlowReconciliation"] = observations

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
    if suite.countTestCases() != 5:
        raise SystemExit("Installed image case inventory must contain exactly five cases")
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
        "scope": "installed image inventory, default-off, native routes, invalid startup and actual operator flow reconciliation; not full Scenario C",
    }
    report["accepted"] = (
        result.wasSuccessful() and result.testsRun == 5 and not result.skipped
        and before == after and len(InstalledImage.receipt.get("installedJarSha256", {})) == 3
    )
    args.report.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({k: v for k, v in report.items() if k not in ("sourceBefore", "sourceAfter")}, sort_keys=True))
    return not report["accepted"]


if __name__ == "__main__":
    raise SystemExit(main())
