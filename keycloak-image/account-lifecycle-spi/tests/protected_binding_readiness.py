"""Public login remains available after a reviewed protected binding drifts."""

import base64
import copy
import hashlib
import json
import subprocess
import time
import unittest
import uuid
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from lifecycle_fixture import ACTORS, SUBJECTS, IMAGE, INSTALLER, REALM, call
from protected_resources import require_active
import test_protected_invitations as protected


class NativeFixture(protected.ProtectedInvitations):
    """Existing two-boot fixture, explicitly owned by the executed test method."""

    @classmethod
    def stop(cls):
        subprocess.run(
            ["docker", "rm", "-f", cls.name],
            check=True,
            capture_output=True,
            timeout=30,
        )
        if hashlib.sha256(cls.jar_path.read_bytes()).hexdigest() != cls.jar_sha256:
            raise AssertionError("Native provider changed during execution")


def request(base, method, path, body=None, bearer=None, form=False):
    headers = {
        "Content-Type": (
            "application/x-www-form-urlencoded" if form else "application/json"
        )
    }
    if bearer is not None:
        headers["Authorization"] = "Bearer " + bearer
    data = (
        None
        if body is None
        else (urlencode(body).encode() if form else json.dumps(body).encode())
    )
    try:
        response = urlopen(
            Request(base + path, method=method, data=data, headers=headers), timeout=5
        )
    except HTTPError as error:
        response = error
    with response:
        raw = response.read()
        return (
            response.code,
            json.loads(raw) if raw else None,
            response.headers.get("Cache-Control", ""),
        )


def inspect_owned():
    return json.loads(
        subprocess.run(
            ["docker", "inspect", NativeFixture.name],
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        ).stdout
    )[0]


def config_values(container):
    return dict(value.split("=", 1) for value in container["Config"]["Env"])


class BindingReadiness(unittest.TestCase):
    # Deliberately no setUpClass: startup failures occur inside an executed case.
    observation = {}

    def clean_native(self):
        NativeFixture.doClassCleanups()
        self.assertEqual([], NativeFixture.tearDown_exceptions)

    def runtime(self, baseline, protected_config):
        current = inspect_owned()
        self.assertEqual(
            "true", current["Config"]["Labels"]["oriso-protected-receiver-test"]
        )
        self.assertEqual(1024**3, current["HostConfig"]["Memory"])
        self.assertEqual(2_000_000_000, current["HostConfig"]["NanoCpus"])
        self.assertEqual(baseline["Image"], current["Image"])
        env = config_values(current)
        self.assertEqual(protected_config, env["ORISO_PROTECTED_INVITATIONS_CONFIG"])
        self.assertEqual("true", env["ORISO_PROTECTED_INVITATIONS_ENABLED"])
        self.assertEqual("true", env["ORISO_ACCOUNT_LIFECYCLE_ENABLED"])
        self.assertEqual("FIVE_ACTORS", env["TASK_IDENTITY_MODEL"])
        self.assertEqual(
            "-Xms128m -Xmx512m -XX:ActiveProcessorCount=2", env["JAVA_OPTS_APPEND"]
        )
        jar = [
            m
            for m in current["Mounts"]
            if m["Destination"] == "/opt/keycloak/providers/account-lifecycle-spi.jar"
        ]
        self.assertEqual(1, len(jar))
        self.assertFalse(jar[0]["RW"])
        self.assertEqual(str(NativeFixture.jar_path), jar[0]["Source"])
        volume = [
            m for m in current["Mounts"] if m["Destination"] == "/opt/keycloak/data"
        ]
        self.assertEqual(1, len(volume))
        self.assertEqual(NativeFixture.native_volume, volume[0]["Name"])
        self.assertEqual("volume", volume[0]["Type"])
        self.assertEqual(
            "true",
            subprocess.run(
                [
                    "docker",
                    "volume",
                    "inspect",
                    "--format",
                    '{{ index .Labels "oriso-protected-receiver-test" }}',
                    NativeFixture.native_volume,
                ],
                check=True,
                capture_output=True,
                text=True,
                timeout=15,
            ).stdout.strip(),
        )
        self.assertEqual(
            1,
            len(
                subprocess.run(
                    [
                        "docker",
                        "ps",
                        "-aq",
                        "--filter",
                        "label=oriso-protected-receiver-test=true",
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                    timeout=15,
                ).stdout.split()
            ),
        )
        return current

    def login(self):
        return request(
            NativeFixture.base,
            "POST",
            "/realms/" + REALM + "/protocol/openid-connect/token",
            {
                "client_id": "protected-human-web",
                "grant_type": "password",
                "username": "reviewed-human",
                "password": protected.HUMAN_PASSWORD,
                "scope": "openid",
            },
            form=True,
        )

    def validate_observed_human(self, helper, bearer):
        payload = bearer.split(".")[1]
        claims = json.loads(
            base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
        )
        self.assertEqual(NativeFixture.human_subject, claims["sub"])
        self.assertEqual(protected.ISSUER, claims["iss"])
        self.assertEqual("protected-human-web", claims["azp"])
        self.assertEqual("0", claims["tenantId"])
        aud = claims["aud"]
        self.assertEqual({"userservice"}, set([aud] if isinstance(aud, str) else aud))
        self.assertEqual(
            {"agency-admin", "tenant-admin"}, set(claims["realm_access"]["roles"])
        )
        self.assertGreater(claims["exp"], time.time())
        status, value, _ = request(
            NativeFixture.base,
            "GET",
            "/realms/" + REALM + "/protocol/openid-connect/userinfo",
            bearer=bearer,
        )
        self.assertEqual(200, status)
        self.assertEqual(claims["sub"], value["sub"])
        status, value = call(
            NativeFixture.base,
            "POST",
            "/realms/master/protocol/openid-connect/token",
            {
                "client_id": "admin-cli",
                "grant_type": "password",
                "username": "synthetic-installer",
                "password": INSTALLER,
            },
            form=True,
        )
        self.assertEqual(200, status)
        NativeFixture.installer = value["access_token"]
        native = helper.admin("GET", "/users/" + claims["sub"])
        self.assertTrue(native["enabled"])
        self.assertIsNone(native.get("serviceAccountClientId"))
        self.assertEqual(["0"], native["attributes"]["tenantId"])
        self.assertEqual([], helper.admin("GET", "/users/" + claims["sub"] + "/groups"))
        self.assertEqual(
            {"agency-admin", "tenant-admin"},
            {
                r["name"]
                for r in helper.admin(
                    "GET", "/users/" + claims["sub"] + "/role-mappings/realm/composite"
                )
            },
        )
        self.assertFalse(
            helper.admin("GET", "/users/" + claims["sub"] + "/role-mappings").get(
                "clientMappings"
            )
        )
        self.assertTrue(
            any(
                s["id"] == claims["sid"]
                for s in helper.admin("GET", "/users/" + claims["sub"] + "/sessions")
            )
        )
        clients = helper.admin("GET", "/clients?clientId=protected-human-web")
        self.assertEqual(1, len(clients))
        client = helper.admin("GET", "/clients/" + clients[0]["id"])
        self.assertTrue(client["enabled"])
        self.assertTrue(client["standardFlowEnabled"])
        self.assertFalse(client["serviceAccountsEnabled"])
        self.assertFalse(client["fullScopeAllowed"])
        self.observation["driftBootNativeUserinfoAndCurrentSessionVerified"] = True

    def test_binding_drift_keeps_native_login_and_protected_unavailable(self):
        type(self).observation = {}
        o = self.observation
        self.addCleanup(self.clean_native)
        NativeFixture.setUpClass()
        helper = NativeFixture("runTest")
        self.assertTrue(NativeFixture.configuration_checked)
        self.assertEqual(2, len(NativeFixture.native_image_ids))
        self.assertEqual(1, len(set(NativeFixture.native_image_ids)))
        bearer = helper.human()
        self.assertEqual(
            ["seed", "configured"], [p["stage"] for p in NativeFixture.preconditions]
        )
        self.assertTrue(
            all(
                p["currentNativeSession"] and p["nativeUserinfoValidatedToken"]
                for p in NativeFixture.preconditions
            )
        )
        self.assertEqual(NativeFixture.realm_id, helper.admin("GET")["id"])
        for actor, (client_id, _) in ACTORS.items():
            clients = helper.admin("GET", "/clients?clientId=" + client_id)
            self.assertEqual(1, len(clients))
            self.assertEqual(NativeFixture.client_ids[actor], clients[0]["id"])
            self.assertEqual(
                SUBJECTS[actor],
                helper.admin(
                    "GET", "/clients/" + clients[0]["id"] + "/service-account-user"
                )["id"],
            )
        o["allFiveCurrentNativeClientLinksVerified"] = True
        before_count = helper.admin("GET", "/users/count")
        status, value = call(
            helper.base,
            "PUT",
            helper.endpoint(str(uuid.uuid4())),
            {"scope": helper.scope()},
            bearer,
        )
        o["validBindingApproveStatus"] = status
        self.assertEqual(201, status)
        self.assertEqual("AUTHORIZED", value["state"])
        self.assertEqual(before_count, helper.admin("GET", "/users/count"))
        o["sameJarValidBindingHumanApproveAndNoAccountVerified"] = True
        bearer = None
        baseline = inspect_owned()
        protected_config = config_values(baseline)["ORISO_PROTECTED_INVITATIONS_CONFIG"]
        self.runtime(baseline, protected_config)
        o["installedConfigurationSHA256"] = hashlib.sha256(
            protected_config.encode()
        ).hexdigest()
        o["validNativeHumanRealmSessionAndRuntimeVerified"] = True
        realm_before = helper.admin("GET")
        human_before = helper.admin("GET", "/users/" + NativeFixture.human_subject)
        path = "/groups/" + NativeFixture.protected_group_id
        group = helper.admin("GET", path)
        self.assertEqual("/protected-admins/platform-admins", group["path"])
        roles_before = helper.admin("GET", path + "/role-mappings")
        changed = copy.deepcopy(group)
        changed["name"] = "platform-admins-binding-drift"
        helper.admin("PUT", path, changed)
        actual = helper.admin("GET", path)
        self.assertEqual(group["id"], actual["id"])
        self.assertEqual(changed["name"], actual["name"])
        self.assertEqual(
            "/protected-admins/platform-admins-binding-drift", actual["path"]
        )
        self.assertEqual(
            {k: v for k, v in group.items() if k not in {"name", "path"}},
            {k: v for k, v in actual.items() if k not in {"name", "path"}},
        )
        self.assertEqual(roles_before, helper.admin("GET", path + "/role-mappings"))
        self.assertEqual(realm_before, helper.admin("GET"))
        self.assertEqual(
            human_before, helper.admin("GET", "/users/" + NativeFixture.human_subject)
        )
        self.assertEqual(before_count, helper.admin("GET", "/users/count"))
        self.assertEqual(
            protected_config,
            config_values(inspect_owned())["ORISO_PROTECTED_INVITATIONS_CONFIG"],
        )
        o["exactNativeGroupNameOnlyDriftVerified"] = True
        NativeFixture.phase = "binding-drift-restart"
        subprocess.run(
            ["docker", "stop", "-t", "5", NativeFixture.name],
            check=True,
            capture_output=True,
            timeout=30,
        )
        subprocess.run(
            ["docker", "rm", NativeFixture.name],
            check=True,
            capture_output=True,
            timeout=15,
        )
        command = NativeFixture.command.copy()
        index = command.index(IMAGE)
        command[index:index] = [
            "-e",
            "ORISO_PROTECTED_INVITATIONS_ENABLED=true",
            "-e",
            "ORISO_PROTECTED_INVITATIONS_CONFIG=" + protected_config,
        ]
        command.append("--verbose")
        NativeFixture.memoryStart()
        subprocess.run(command, check=True, capture_output=True, timeout=30)
        NativeFixture.refresh_endpoint("binding-drift-restart")
        o["actualPublishedMappingObserved"] = True
        third = self.runtime(baseline, protected_config)
        NativeFixture.native_image_ids.append(third["Image"])
        o["sameImageJarConfigVolumeAndResourceCapsVerified"] = True
        deadline = time.monotonic() + 180
        status = None
        bearer = None
        while time.monotonic() < deadline:
            require_active("binding-drift-native-login")
            try:
                status, value, _ = self.login()
                o["driftBootHumanLoginStatus"] = status
                if status == 200:
                    bearer = value["access_token"]
                    break
            except (URLError, TimeoutError, OSError) as error:
                o["driftBootConnectionExceptionType"] = type(error).__name__
            state = inspect_owned()["State"]
            if not state["Running"]:
                self.assertFalse(state["OOMKilled"])
                self.assertNotEqual(0, state["ExitCode"])
                output = subprocess.run(
                    ["docker", "logs", NativeFixture.name],
                    capture_output=True,
                    text=True,
                    timeout=15,
                )
                native_output = output.stdout + output.stderr
                frames = {
                    "factory": "ProtectedInvitationFactory." in native_output,
                    "installation": "ProtectedInvitationConfiguration.validateInstallation("
                    in native_output,
                    "profile": "ProtectedInvitationConfiguration.validateProfile("
                    in native_output,
                    "forbidden": "jakarta.ws.rs.ForbiddenException" in native_output,
                }
                self.assertTrue(all(frames.values()))
                o["protectedValidationSourceFrames"] = frames
                o["nativeExitCode"] = state["ExitCode"]
                o["nonzeroNativeExitWithoutOom"] = True
                # Observe this actual captured mapping again after the proven exit.
                try:
                    status, _, _ = self.login()
                    o["driftBootHumanLoginStatus"] = status
                except (URLError, TimeoutError, OSError) as error:
                    o["driftBootConnectionExceptionType"] = type(error).__name__
                    status = None
                o["classifiedNativeBindingExitAndLoginUnavailable"] = status != 200
                break
            time.sleep(1)
        o["thirdBootObservationFinished"] = True
        NativeFixture.phase = "binding-drift-login-observed"
        # The old provider aborts Keycloak: this is the one intended public RED.
        self.assertEqual(200, status)
        self.validate_observed_human(helper, bearer)
        NativeFixture.phase = "binding-drift-protected-request"
        status, _, cache = request(
            helper.base,
            "PUT",
            helper.endpoint(str(uuid.uuid4())),
            {"scope": helper.scope()},
            bearer,
        )
        o["unreadyProtectedApprovalStatus"] = status
        o["unreadyResponseNoStore"] = "no-store" in {
            v.strip().lower() for v in cache.split(",")
        }
        self.assertEqual(503, status)
        self.assertTrue(o["unreadyResponseNoStore"])
        self.assertEqual(realm_before, helper.admin("GET"))
        self.assertEqual(
            human_before, helper.admin("GET", "/users/" + NativeFixture.human_subject)
        )
        self.assertEqual(before_count, helper.admin("GET", "/users/count"))
        self.assertEqual(actual, helper.admin("GET", path))
        self.assertEqual(roles_before, helper.admin("GET", path + "/role-mappings"))
        o["postDriftRealmHumanGroupAndAccountCountUnchanged"] = True
        bearer = None
