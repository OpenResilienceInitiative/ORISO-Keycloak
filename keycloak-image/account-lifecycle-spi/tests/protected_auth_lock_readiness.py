"""Real public unauthenticated/proof-invalid requests must not wait on the realm row."""

import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
import uuid
import zipfile

from lifecycle_fixture import ACTORS, SUBJECTS, REALM, call, canonical, mac
from protected_binding_readiness import NativeFixture, BindingReadiness, config_values, inspect_owned
from protected_resources import require_active
from run_protected import digest

PREFIX = "ORISO_PROOF_AUTH_LOCK_V1 "
COMPANION_TARGET = "/opt/keycloak/providers/oriso-proof-auth-lock.jar"
CONTROL_TARGET = "/opt/keycloak/proof-auth-lock"
FIELDS = {"schema", "index", "phase", "runtimeH2Pinned", "nativeTransactionOwned",
          "actualRealmRowHeld", "matchingBlockedRequest", "workerFailed", "selectorObservation"}
SELECTOR_FIELDS = {"holderWaiterObserved", "distinctSessionObserved", "blockedStateObserved",
    "realmTableObserved", "idPredicateObserved", "forUpdateObserved", "exactBoundRealmParameterObserved"}
ROUTES = ("approve", "human-cancel", "machine-cancel", "status", "create", "owned-read",
          "commit", "recover", "compensate")
PRECONDITIONS = ("allFiveCurrentNativeClientLinksVerified", "currentHumanAndInstalledConfigurationVerified",
    "actualHumanApprovalDisabledCreateAndOwnedReadVerified", "actualCanonicalMachineTokensVerified",
    "runtimeH2ArtifactAndVersionVerified", "sameRuntimeMainCompanionAndReadOnlyControlVerified",
    "allUnlockedAuthenticationDenialsVerified", "allNineActualRollbackWitnessesVerified",
    "postProbeValidHumanApproveAndUnchangedNativeStateVerified")


def classify(summary):
    o = summary.get("readinessObservation", {})
    rows = o.get("routeObservations", [])
    if not (summary.get("executed") == 1 and summary.get("errors") == 0 and summary.get("skipped") == 0
            and all(o.get(k) is True for k in PRECONDITIONS)
            and len(summary.get("nativeImageIds", [])) == 2
            and len(set(summary["nativeImageIds"])) == 1
            and len(rows) == 9 and [r.get("route") for r in rows] == list(ROUTES)):
        return "INPUT_OR_FIXTURE_ERROR"
    for row in rows:
        expected = 401 if row["route"] in {"approve", "human-cancel"} else 403
        if row.get("unlockedStatus") != expected or row.get("afterReleaseStatus") != expected:
            return "INPUT_OR_FIXTURE_ERROR"
        if not all(row.get(k) is True for k in ["actualRealmLockOwned", "actualRollbackNoCommitVerified"]):
            return "INPUT_OR_FIXTURE_ERROR"
        if row.get("completedBeforeRelease") is not True and row.get("matchingBlockedRequest") is not True:
            return "INPUT_OR_FIXTURE_ERROR"
    blocked = any(r["matchingBlockedRequest"] is True for r in rows)
    if blocked and summary.get("failures") == 1:
        return "GENUINE_UNAUTHENTICATED_PROTECTED_REQUEST_WAITS_FOR_REALM_ROW_RED"
    if not blocked and summary.get("failures") == 0 and all(r["completedBeforeRelease"] is True for r in rows):
        return "GREEN"
    return "BEHAVIOR_FAILURE"


def records(fixture):
    native = inspect_owned(fixture)
    if native["Config"]["Labels"].get("oriso-protected-receiver-test") != "true":
        raise AssertionError("Exact owned native container required")
    # Raw process output is transient; persist only strictly parsed fixed records.
    output = subprocess.run(["docker", "logs", "--tail", "500", fixture.name],
        check=True, capture_output=True, text=True, timeout=15)
    result = []
    for line in (output.stdout + "\n" + output.stderr).splitlines():
        if not line.startswith(PREFIX):
            continue
        value = json.loads(line[len(PREFIX):])
        if (set(value) != FIELDS or type(value["schema"]) is not int or value["schema"] != 1
                or type(value["index"]) is not int or not -1 <= value["index"] <= 9
                or value["phase"] not in {"INERT", "ARMED", "LOCKED", "BLOCKED", "RELEASED", "COMPLETE", "FAILED"}
                or any(type(value[k]) is not bool for k in FIELDS - {"schema", "index", "phase", "selectorObservation"})
                or type(value["selectorObservation"]) is not dict or set(value["selectorObservation"]) != SELECTOR_FIELDS
                or any(type(v) is not bool for v in value["selectorObservation"].values())):
            raise AssertionError("Invalid fixed proof process record")
        result.append(value)
    if len(result) != len({(v["index"], v["phase"]) for v in result}):
        raise AssertionError("Duplicate fixed proof process record")
    if any(v["workerFailed"] for v in result):
        raise AssertionError("Actual proof worker failed")
    return result


def wait_record(fixture, index, phase, deadline):
    while time.monotonic() < deadline:
        require_active("protected-auth-lock-witness")
        found = [r for r in records(fixture) if r["index"] == index and r["phase"] == phase]
        if found:
            if len(found) != 1:
                raise AssertionError("Unique owned proof phase required")
            return found[0]
        time.sleep(0.025)
    raise AssertionError("Actual proof phase did not occur before finite deadline")


class AuthLockFixture(NativeFixture):
    @classmethod
    def setUpClass(cls):
        cls.companion_path = Path(os.environ["LIFECYCLE_AUTH_LOCK_COMPANION_JAR"]).resolve()
        if not cls.companion_path.is_file():
            raise AssertionError("Separately compiled proof companion required")
        cls.companion_sha256 = digest(cls.companion_path)
        cls.proof_boot_phases = []
        cls.control = Path(tempfile.mkdtemp(prefix="oriso-auth-lock-", dir=os.environ["RUNNER_TEMP"]))
        cls.control.chmod(0o755)
        cls.addClassCleanup(lambda: shutil.rmtree(cls.control))
        super().setUpClass()

    @classmethod
    def ready(cls):
        super().ready()
        boot = records(cls)
        expected = "ARMED" if config_values(inspect_owned(cls)).get("ORISO_PROTECTED_INVITATIONS_ENABLED") == "true" else "INERT"
        if len(boot) != 1 or boot[0]["phase"] != expected or boot[0]["index"] != -1:
            raise AssertionError("Exact inert/configured boot proof required")
        cls.proof_boot_phases.append(expected)

    @classmethod
    def memoryStart(cls):
        source = str(cls.companion_path) + ":" + COMPANION_TARGET + ":ro"
        if source not in cls.command:
            index = cls.command.index("quay.io/keycloak/keycloak@sha256:9b0330756022422149aa6502eb2def8cd47c6e1b000c7c65cdb13e7c0133e992")
            cls.command[index:index] = ["-v", source, "-v", str(cls.control) + ":" + CONTROL_TARGET + ":ro"]
        super().memoryStart()


class AuthLockReadiness(unittest.TestCase):
    observation = {}

    def clean_native(self):
        AuthLockFixture.doClassCleanups()
        self.assertEqual([], AuthLockFixture.tearDown_exceptions)

    def test_untrusted_public_requests_reject_before_waiting_for_the_realm_row(self):
        type(self).observation = {};o = self.observation
        self.addCleanup(self.clean_native)
        AuthLockFixture.setUpClass();AuthLockFixture.phase = "auth-lock-native-preconditions";helper = AuthLockFixture("runTest")
        self.assertTrue(AuthLockFixture.configuration_checked)
        for actor, (client, _) in ACTORS.items():
            clients = helper.admin("GET", "/clients?clientId=" + client)
            self.assertEqual(1, len(clients))
            self.assertEqual(AuthLockFixture.client_ids[actor], clients[0]["id"])
            self.assertEqual(SUBJECTS[actor], helper.admin("GET", "/clients/" + clients[0]["id"] + "/service-account-user")["id"])
        o["allFiveCurrentNativeClientLinksVerified"] = True
        self.assertTrue(helper.human(record=False))
        o["currentHumanAndInstalledConfigurationVerified"] = True
        approval, attempt, scope, issued, create = helper.approved_creation()
        status, opened = helper.protected_machine_request("create", approval, create, actor="ACCOUNT_CREATE", attempt=attempt)
        self.assertEqual(201, status)
        native = helper.admin("GET", "/users/" + opened["accountId"])
        self.assertFalse(native["enabled"])
        groups = helper.admin("GET", "/users/" + opened["accountId"] + "/groups")
        self.assertEqual(["/pending-provisioning"], [v["path"] for v in groups])
        read = {k: create[k] for k in ("approvalReceipt", "scopeDigest", "authorizationRevision", "creationFingerprint", "execution")}
        read.update(accountId=opened["accountId"], creationProof=opened["creationProof"])
        status, projection = helper.protected_machine_request("owned-read", approval, read, actor="ACCOUNT_CREATE", attempt=attempt)
        self.assertEqual(200, status);self.assertEqual(opened["accountId"], projection["id"])
        o["actualHumanApprovalDisabledCreateAndOwnedReadVerified"] = True
        baseline = inspect_owned(AuthLockFixture)
        encoded_config = config_values(baseline)["ORISO_PROTECTED_INVITATIONS_CONFIG"]
        BindingReadiness("runTest").runtime(baseline, encoded_config, AuthLockFixture)
        for destination, source in [(COMPANION_TARGET, str(AuthLockFixture.companion_path)), (CONTROL_TARGET, str(AuthLockFixture.control))]:
            mount = [m for m in baseline["Mounts"] if m["Destination"] == destination]
            self.assertEqual(1, len(mount));self.assertEqual(source, mount[0]["Source"]);self.assertFalse(mount[0]["RW"])
        self.assertEqual(AuthLockFixture.companion_sha256, digest(AuthLockFixture.companion_path))
        o["sameRuntimeMainCompanionAndReadOnlyControlVerified"] = True
        AuthLockFixture.phase = "auth-lock-runtime-h2-artifact"
        self.assertEqual(["INERT", "ARMED"], AuthLockFixture.proof_boot_phases)
        paths = subprocess.run(["docker", "exec", AuthLockFixture.name, "find", "/opt/keycloak/lib/lib/main", "-maxdepth", "1", "-name", "com.h2database.h2-*.jar"],
            check=True, capture_output=True, text=True, timeout=15).stdout.splitlines()
        self.assertEqual(["/opt/keycloak/lib/lib/main/com.h2database.h2-2.4.240.jar"], paths)
        copied = AuthLockFixture.control.parent / ("oriso-auth-lock-h2-" + uuid.uuid4().hex + ".jar")
        self.addCleanup(lambda: copied.unlink(missing_ok=True))
        subprocess.run(["docker", "cp", AuthLockFixture.name + ":" + paths[0], str(copied)], check=True, capture_output=True, timeout=15)
        with zipfile.ZipFile(copied) as jar:
            manifest = jar.read("META-INF/MANIFEST.MF").decode()
            self.assertIn("Implementation-Version: 2.4.240\r\n", manifest)
        o["runtimeH2ArtifactSHA256"] = digest(copied)
        o["runtimeH2ArtifactAndVersionVerified"] = True
        copied.unlink()
        boot = records(AuthLockFixture)
        self.assertEqual(1, len(boot));self.assertEqual("ARMED", boot[0]["phase"])
        self.assertEqual(-1, boot[0]["index"])
        tokens = {a: helper.token(a) for a in ["SETUP", "ACCOUNT_CREATE"]}
        config = json.loads(encoded_config)
        for actor, token in tokens.items():
            claims = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=" * (-len(token.split(".")[1]) % 4)))
            self.assertEqual(AuthLockFixture.native_issuer, claims["iss"])
            self.assertEqual(SUBJECTS[actor], claims["sub"])
            self.assertEqual(set(config["machineAudienceSets"][actor]), set(claims["aud"]))
            self.assertGreater(claims["exp"], time.time())
        o["actualCanonicalMachineTokensVerified"] = True
        query = {"scopeDigest": issued["scopeDigest"], "workflowId": scope["workflowId"], "inviteId": scope["inviteId"],
            "authorizationRevision": 1, "attemptId": attempt, "approvalRequestDigest": issued["approvalRequestDigest"]}
        cancel = {k: query[k] for k in query if k != "attemptId"}
        cancel.update(cancellationId=str(uuid.uuid4()), reason="REVOKED", absentScope=None)
        commit = {**read, "localCommit": {"journalVersion": 1, "outboxId": str(uuid.uuid4()), "effectsDigest": "a" * 64}}
        recover = {k: create[k] for k in ("approvalReceipt", "scopeDigest", "authorizationRevision", "creationFingerprint", "acceptanceClaim")}
        recover.update(expectedGeneration=0, recoveryId=str(uuid.uuid4()))
        compensate = {**read, "localCleanup": {"journalVersion": 1, "outboxId": str(uuid.uuid4()), "effectsDigest": "b" * 64}}
        bodies = [ {"scope": scope}, cancel, cancel, query, create, read, commit, recover, compensate ]
        requests = []
        for index, route in enumerate(ROUTES):
            body = bodies[index]
            if index < 2:
                method = "PUT" if index == 0 else "POST"
                path = helper.endpoint(approval, "" if index == 0 else "/cancel")
                requests.append(lambda method=method, path=path, body=body: call(helper.base, method, path, body)[0])
            else:
                operation = "cancel" if index == 2 else route
                actor = "SETUP" if index < 4 else "ACCOUNT_CREATE"
                method = "PUT" if route == "create" else "POST"
                path = helper.endpoint(approval, "/" + operation if index < 4 else "/attempts/" + attempt + ("" if route == "create" else "/" + route))
                target = "realm/" + helper.realm_id + "/protected-invitation/" + approval + ("" if index < 4 else "/account-attempt/" + attempt)
                now = int(time.time())
                claims = {"iss": "userservice", "aud": "oriso-protected-invitations", "purpose": "INVITE_RESERVATIONS" if actor == "SETUP" else "ACCOUNT_PROVISIONING",
                    "operation": "protected-invitation." + operation if index < 4 else "protected-account." + ("creation-recover" if route == "recover" else route),
                    "method": method, "actor": actor, "realm": REALM, "target": target, "taskClient": ACTORS[actor][0], "taskSubject": SUBJECTS[actor],
                    "payloadDigest": mac("protected-invitation-payload/v1", body), "jti": str(uuid.uuid4()), "nonce": uuid.uuid4().hex, "iat": now, "exp": now + 60}
                proof = base64.urlsafe_b64encode(canonical(claims)).decode().rstrip("=") + "." + "A" * 43
                requests.append(lambda method=method, path=path, body=body, bearer=tokens[actor], proof=proof: call(helper.base, method, path, body, bearer, proof=proof)[0])
        AuthLockFixture.phase = "auth-lock-unlocked-controls"
        unlocked = [request() for request in requests]
        self.assertEqual([401, 401] + [403] * 7, unlocked)
        o["allUnlockedAuthenticationDenialsVerified"] = True
        count = helper.admin("GET", "/users/count")
        observations = [];o["routeObservations"] = observations
        AuthLockFixture.phase = "auth-lock-held-public-http"
        with ThreadPoolExecutor(max_workers=1) as executor:
            for index, request in enumerate(requests):
                (AuthLockFixture.control / (str(index) + ".arm")).touch(mode=0o644)
                held = wait_record(AuthLockFixture, index, "LOCKED", time.monotonic() + 5)
                self.assertTrue(all(held[k] for k in ["runtimeH2Pinned", "nativeTransactionOwned", "actualRealmRowHeld"]))
                future = executor.submit(request)
                blocked = False;deadline = time.monotonic() + 1.5
                try:
                    while time.monotonic() < deadline:
                        current = records(AuthLockFixture)
                        blocked = any(r["index"] == index and r["phase"] == "BLOCKED" and r["matchingBlockedRequest"] for r in current)
                        if blocked or future.done(): break
                        time.sleep(0.025)
                    completed = future.done()
                finally:
                    (AuthLockFixture.control / (str(index) + ".release")).touch(mode=0o644)
                released = wait_record(AuthLockFixture, index, "RELEASED", time.monotonic() + 2)
                status = future.result(timeout=5)
                blocked = released["matchingBlockedRequest"]
                observations.append({"route": ROUTES[index], "unlockedStatus": unlocked[index], "afterReleaseStatus": status,
                    "completedBeforeRelease": completed, "matchingBlockedRequest": blocked,
                    "selectorObservation": released["selectorObservation"],
                    "actualRealmLockOwned": all(held[k] for k in ["runtimeH2Pinned", "nativeTransactionOwned", "actualRealmRowHeld"]),
                    "actualRollbackNoCommitVerified": released["nativeTransactionOwned"] and released["actualRealmRowHeld"] and not released["workerFailed"]})
        wait_record(AuthLockFixture, 9, "COMPLETE", time.monotonic() + 2)
        o["allNineActualRollbackWitnessesVerified"] = True
        AuthLockFixture.phase = "auth-lock-post-rollback-positive"
        self.assertEqual(native, helper.admin("GET", "/users/" + opened["accountId"]))
        self.assertEqual(groups, helper.admin("GET", "/users/" + opened["accountId"] + "/groups"))
        self.assertEqual(count, helper.admin("GET", "/users/count"))
        status, _ = call(helper.base, "PUT", helper.endpoint(str(uuid.uuid4())), {"scope": helper.scope()}, helper.human(record=False))
        self.assertEqual(201, status)
        o["postProbeValidHumanApproveAndUnchangedNativeStateVerified"] = True
        self.assertTrue(all(r["completedBeforeRelease"] and not r["matchingBlockedRequest"] for r in observations))


def companion_evidence(fixture=AuthLockFixture):
    result = {"expectedNativeBoots": 2}
    if not hasattr(fixture, "companion_path"):
        return result
    jar = fixture.companion_path
    with zipfile.ZipFile(jar) as archive:
        entries = {n: hashlib.sha256(archive.read(n)).hexdigest() for n in archive.namelist()}
        if any(not n.startswith("org/oriso/keycloak/lifecycle/proof/") and n != "META-INF/services/org.keycloak.services.resource.RealmResourceProviderFactory" for n in entries):
            raise AssertionError("Unexpected companion archive entry")
    with zipfile.ZipFile(fixture.jar_path) as archive:
        if any(n.startswith("org/oriso/keycloak/lifecycle/proof/") for n in archive.namelist()):
            raise AssertionError("Companion appeared in product JAR")
    result.update(companionJarSHA256=fixture.companion_sha256, companionJarStable=digest(jar) == fixture.companion_sha256,
        companionAbsentFromMainJar=True, companionJarEntriesSHA256=entries,
        ownedControlDirectoryRemoved=not fixture.control.exists(), companionBootPhases=fixture.proof_boot_phases)
    return result
