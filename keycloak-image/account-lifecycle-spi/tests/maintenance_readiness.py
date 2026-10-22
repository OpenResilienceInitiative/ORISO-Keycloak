"""One executed third-boot check; unused human-profile drift grants no machine authority."""
import copy
import hashlib
import json
import subprocess
import signal
import unittest
import uuid
from urllib.error import URLError

from lifecycle_fixture import ACTORS, IMAGE, REALM, SUBJECTS, call
from maintenance_human_fixture import HumanMaintenanceFixture


def classify(o):
    required = ("reviewedUnusedProfileInstalled", "exactUnusedGroupNameOnlyDrift",
                "primaryHumanAndOrdinaryMappingUnchanged", "sameJarImageConfigVolumeAndCaps")
    if o.get("validHumanReadStatus") != 200 or not all(o.get(k) is True for k in required):
        return "INPUT_OR_FIXTURE_ERROR"
    if o.get("driftHumanLoginStatus") == 0 and not (o.get("nativeExitedNonzeroWithoutOom") is True
            and o.get("bindingValidationSourceWitness") is True):
        return "INPUT_OR_FIXTURE_ERROR"
    if (o.get("nativeExitedNonzeroWithoutOom") is True
            and o.get("bindingValidationSourceWitness") is True
            and o.get("driftHumanLoginStatus") == 0):
        return "GENUINE_HUMAN_BINDING_ABORTS_NATIVE_LOGIN_RED"
    if (o.get("driftHumanLoginStatus") == 200 and o.get("selfStatus") == 503
            and o.get("otpStatus") == 503 and o.get("bothUnavailableNoStore") is True
            and o.get("ordinaryMachineCreationReadDeleteVerified") is True
            and o.get("wrongActorAndProofDeniedBeforeReadiness") is True):
        return "GREEN"
    return "BEHAVIOR_FAILURE"


class ReadinessFixture(HumanMaintenanceFixture, unittest.TestCase):
    @classmethod
    def install_unused_readiness_profile(cls):
        return True

    @classmethod
    def reviewed_self_operations(cls):
        return ["account.read", "otp.read"]

    @classmethod
    def extra_launch_arguments(cls):
        from test_otp_scoped import ScopedOtpRead
        return ScopedOtpRead.extra_launch_arguments()


class HumanBindingReadiness(unittest.TestCase):
    observation = {}

    def cleanup(self):
        ReadinessFixture.doClassCleanups()
        self.assertEqual([], ReadinessFixture.tearDown_exceptions)

    def test_unused_reviewed_profile_drift_keeps_login_machine_and_human503(self):
        self.addCleanup(self.cleanup)
        def deadline(signum, frame):
            raise AssertionError("Finite600s human binding proof deadline")
        previous = signal.signal(signal.SIGALRM, deadline)
        signal.setitimer(signal.ITIMER_REAL, 600)
        def release_deadline():
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)
        self.addCleanup(release_deadline)
        type(self).observation = {}
        o = self.observation
        ReadinessFixture.setUpClass()
        h = ReadinessFixture("runTest")
        human = h.human()
        from test_otp_scoped import ScopedOtpRead
        target = ScopedOtpRead.target(h)
        status, _ = h.invoke("read", {"target": target}, human, 200)
        o["validHumanReadStatus"] = status
        self.assertEqual(200, status)
        self.assertEqual(200, ScopedOtpRead.scoped_read(h, human, target, 200)[0])
        inspect = lambda: json.loads(subprocess.run(["docker", "inspect", h.name], check=True,
            capture_output=True, text=True, timeout=15).stdout)[0]
        before = inspect()
        active = subprocess.run(["docker", "ps", "-q", "--filter", "ancestor=" + IMAGE],
            check=True, capture_output=True, text=True, timeout=15).stdout.split()
        self.assertEqual(1, len(active))
        self.assertEqual(1024**3, before["HostConfig"]["Memory"])
        self.assertEqual(2_000_000_000, before["HostConfig"]["NanoCpus"])
        self.assertTrue(all(p["HostIp"] == "127.0.0.1" for p in before["NetworkSettings"]["Ports"]["8080/tcp"]))
        config = next(v for v in before["Config"]["Env"] if v.startswith("ORISO_ACCOUNT_MAINTENANCE_CONFIG="))
        self.assertEqual(config, next(v for v in h.configured_command if v.startswith("ORISO_ACCOUNT_MAINTENANCE_CONFIG=")))
        group = h.admin("GET", "/groups/" + h.unused_readiness_group)
        self.assertEqual("/human-roles/readiness-unused", group["path"])
        self.assertEqual([], h.admin("GET", "/groups/" + group["id"] + "/members"))
        self.assertEqual(2, len(json.loads(config.split("=", 1)[1])["ordinaryProfiles"]))
        o["reviewedUnusedProfileInstalled"] = True
        primary = h.admin("GET", "/users/" + h.account_id)
        roles = h.admin("GET", "/users/" + h.account_id + "/role-mappings/realm/composite")
        ordinary = h.admin("GET", "/groups/" + h.group["id"])
        changed = copy.deepcopy(group); changed["name"] = "readiness-unused-drift"
        h.admin("PUT", "/groups/" + group["id"], changed)
        current = h.admin("GET", "/groups/" + group["id"])
        self.assertEqual(changed["name"], current["name"])
        self.assertEqual("/human-roles/readiness-unused-drift", current["path"])
        for field in ("id", "parentId", "attributes", "realmRoles", "clientRoles"):
            self.assertEqual(group.get(field), current.get(field))
        self.assertEqual(primary, h.admin("GET", "/users/" + h.account_id))
        self.assertEqual(roles, h.admin("GET", "/users/" + h.account_id + "/role-mappings/realm/composite"))
        self.assertEqual(ordinary, h.admin("GET", "/groups/" + h.group["id"]))
        o["exactUnusedGroupNameOnlyDrift"] = True
        o["primaryHumanAndOrdinaryMappingUnchanged"] = True
        subprocess.run(["docker", "stop", "-t", "5", h.name], check=True, capture_output=True, timeout=30)
        subprocess.run(["docker", "rm", h.name], check=True, capture_output=True, timeout=30)
        subprocess.run(h.configured_command, check=True, capture_output=True, timeout=30)
        ReadinessFixture.refresh_endpoint("human-only-drift-third-boot")
        after = inspect()
        self.assertEqual(before["Image"], after["Image"])
        self.assertEqual(before["HostConfig"]["Memory"], after["HostConfig"]["Memory"])
        self.assertEqual(before["HostConfig"]["NanoCpus"], after["HostConfig"]["NanoCpus"])
        self.assertEqual(config, next(v for v in after["Config"]["Env"] if v.startswith("ORISO_ACCOUNT_MAINTENANCE_CONFIG=")))
        self.assertEqual(before["Mounts"], after["Mounts"])
        self.assertEqual(h.jar_sha256, hashlib.sha256(h.jar_path.read_bytes()).hexdigest())
        o["sameJarImageConfigVolumeAndCaps"] = True
        try:
            ReadinessFixture.ready()
        except AssertionError:
            state = inspect()["State"]
            logs = subprocess.run(["docker", "logs", h.name], check=True,
                capture_output=True, text=True, timeout=15)
            text = logs.stdout + logs.stderr
            o["nativeExitedNonzeroWithoutOom"] = (not state["Running"] and state["ExitCode"] != 0
                and state["OOMKilled"] is False and state.get("Error", "") == "")
            o["bindingValidationSourceWitness"] = all(frame in text for frame in (
                "AccountLifecycleFactory", "GeneralPolicy.validateInstallation", "LifecycleJson.deny"))
            try:
                status, _ = call(ReadinessFixture.base, "POST", "/realms/" + REALM
                    + "/protocol/openid-connect/token", {"client_id": "ordinary-human-web", "grant_type": "password",
                    "username": h.creation_input["account"]["username"],
                    "password": h.creation_input["account"]["password"], "scope": "openid"}, form=True)
            except (URLError, OSError, TimeoutError):
                status = 0
            o["driftHumanLoginStatus"] = status
            self.assertEqual("GREEN", classify(o), "Human-only binding drift must preserve native login")
            return
        h.base, h.installer = ReadinessFixture.base, ReadinessFixture.installer
        human = h.human(); o["driftHumanLoginStatus"] = 200
        status, _ = h.invoke("read", {"target": target}, human, 503)
        o["selfStatus"] = status
        self.assertEqual(503, status)
        self_no_store = h.last_response_no_store
        status, _ = ScopedOtpRead.scoped_read(h, human, target, 503)
        o["otpStatus"] = status
        self.assertEqual(503, status)
        o["bothUnavailableNoStore"] = self_no_store and h.last_response_no_store
        from test_maintenance import MaintenancePermissions
        body = {"target": target}
        self.assertEqual(403, MaintenancePermissions.maintenance(h, "read", h.account_id, body,
            actor="ACCOUNT_CREATE", expected_status=403)[0])
        self.assertEqual(403, MaintenancePermissions.maintenance(h, "read", h.account_id, body,
            changes={"payloadDigest": "0" * 64}, expected_status=403)[0])
        o["wrongActorAndProofDeniedBeforeReadiness"] = True
        account, create = MaintenancePermissions.committed(h)
        deletion_target = MaintenancePermissions.target(account, create)
        status, projection = MaintenancePermissions.maintenance(h, "read", account, {"target": deletion_target})
        self.assertEqual(200, status)
        command = {"target": deletion_target, "operationId": str(uuid.uuid4()),
                   "expectedState": projection["state"], "change": {}}
        status, receipt = MaintenancePermissions.maintenance(h, "delete", account, command)
        self.assertEqual(200, status)
        self.assertEqual((200, receipt), MaintenancePermissions.maintenance(h, "delete", account, command))
        o["ordinaryMachineCreationReadDeleteVerified"] = True
        self.assertEqual("GREEN", classify(o))
