#!/usr/bin/env python3
"""Actual native installation boundary; fixture errors never count as behavior RED."""

import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import time
import unittest
import uuid
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from lifecycle_fixture import ACTORS, SUBJECTS, IMAGE, call
from protected_resources import evidence as resource_evidence
from run_protected import (
    SanitizedResult,
    ProofDeadlineReached,
    cleanup_owned,
    digest,
    source_manifest,
    unit_evidence,
    write_xml,
)
import test_protected_invitations as protected

CASES = (
    "extra-denies-prepared-five",
    "missing-required-client",
    "missing-required-service-account",
    "unregistered-technical-human",
    "unregistered-task-role-human",
    "unregistered-inherited-task-human",
    "allowlisted-denied-human",
)


class Installation(protected.ProtectedInvitations):
    @classmethod
    def prepare_installation(cls, helper, configuration):
        # Emit stack locations only to the owned container's private in-memory
        # diagnostic read. The workflow never uploads or prints native logs.
        cls.command.append("--verbose")
        cls.installation_observation = {"case": cls.case}
        cls.installation_refused = False
        cls.mutation_verified = False
        # Verify all five actual client links before the single mutation. No
        # configured example UUID can stand in for these native observations.
        for actor, (client_id, _) in ACTORS.items():
            native_clients = helper.admin("GET", "/clients?clientId=" + client_id)
            helper.assertEqual(1, len(native_clients))
            helper.assertEqual(cls.client_ids[actor], native_clients[0]["id"])
            native = helper.admin(
                "GET", "/clients/" + cls.client_ids[actor] + "/service-account-user"
            )
            helper.assertEqual(SUBJECTS[actor], native["id"])
            # The native client-scoped endpoint resolves getServiceAccount(client).
            # UserRepresentation does not expose the JPA linkage column.
            helper.assertIn(native["id"], configuration["technicalSubjects"])
        cls.installation_observation["allFiveCurrentNativeClientLinksVerified"] = True
        if cls.case == "extra-denies-prepared-five":
            # Actual master-realm installer remains a deny-only identity even
            # though it never existed as an application realm user.
            cls.phase = "inventory-foreign-master-lookup"
            status, native = call(
                cls.base,
                "GET",
                "/admin/realms/master/users?username=synthetic-installer&exact=true",
                token=cls.installer,
            )
            cls.installation_observation["masterLookupStatus"] = status
            cls.installation_observation["masterLookupCount"] = (
                len(native) if isinstance(native, list) else None
            )
            helper.assertEqual(200, status)
            helper.assertEqual(1, len(native))
            foreign = native[0]["id"]
            helper.assertEqual(foreign, str(uuid.UUID(foreign)))
            helper.assertEqual("synthetic-installer", native[0]["username"])
            status, native = call(
                cls.base,
                "GET",
                "/admin/realms/master/users/" + foreign,
                token=cls.installer,
            )
            helper.assertEqual(200, status)
            helper.assertEqual(foreign, native["id"])
            helper.assertEqual("synthetic-installer", native["username"])
            helper.assertIsNone(native.get("federationLink"))
            helper.assertIsNone(native.get("serviceAccountClientId"))
            status, storage = call(
                cls.base,
                "GET",
                "/admin/realms/master/components?type=org.keycloak.storage.UserStorageProvider",
                token=cls.installer,
            )
            helper.assertEqual(200, status)
            helper.assertEqual([], storage)
            cls.installation_observation[
                "masterNativeLocalUserExactIdAndUsernameVerified"
            ] = True
            cls.phase = "inventory-foreign-application-observation"
            # Native UsersResource deliberately returns403 for some missing-ID
            # queries. Never interpret403 as absence. Master native200 and the
            # pinned JPA global USER_ENTITY.ID primary key prove realm distinction.
            cls.installation_observation["foreignApplicationLookupStatus"] = call(
                cls.base,
                "GET",
                "/admin/realms/" + protected.REALM + "/users/" + foreign,
                token=cls.installer,
            )[0]
            cls.phase = "inventory-deleted-deny-create"
            with urlopen(
                Request(
                    cls.base + "/admin/realms/" + protected.REALM + "/users",
                    method="POST",
                    data=json.dumps(
                        {"username": "deleted-oneoff-deny", "enabled": False}
                    ).encode(),
                    headers={
                        "Content-Type": "application/json",
                        "Authorization": "Bearer " + cls.installer,
                    },
                ),
                timeout=30,
            ) as created:
                helper.assertEqual(201, created.status)
                location = created.headers.get("Location")
                helper.assertIsNotNone(location)
                deleted = urlparse(location).path.rsplit("/", 1)[-1]
                created.read()
            helper.assertEqual(deleted, str(uuid.UUID(deleted)))
            cls.phase = "inventory-deleted-deny-native-get"
            native = helper.admin("GET", "/users/" + deleted)
            helper.assertEqual(deleted, native["id"])
            helper.assertEqual("deleted-oneoff-deny", native["username"])
            helper.assertFalse(native["enabled"])
            helper.assertIsNone(native.get("federationLink"))
            cls.phase = "inventory-deleted-deny-native-delete"
            helper.assertEqual(
                204,
                call(
                    cls.base,
                    "DELETE",
                    "/admin/realms/" + protected.REALM + "/users/" + deleted,
                    token=cls.installer,
                )[0],
            )
            cls.phase = "inventory-deleted-deny-fresh-exact-query"
            helper.assertEqual(
                [],
                helper.admin("GET", "/users?username=deleted-oneoff-deny&exact=true"),
            )
            configuration["technicalSubjects"] = sorted(
                configuration["technicalSubjects"] + [foreign, deleted]
            )
            for actor in ACTORS:
                cls.phase = "inventory-prepared-disable-" + actor
                client = helper.admin("GET", "/clients/" + cls.client_ids[actor])
                client["enabled"] = False
                helper.admin("PUT", "/clients/" + cls.client_ids[actor], client)
                helper.assertFalse(
                    helper.admin("GET", "/clients/" + cls.client_ids[actor])["enabled"]
                )
                cls.phase = "inventory-prepared-retained-link-" + actor
                helper.assertEqual(
                    SUBJECTS[actor],
                    helper.admin(
                        "GET",
                        "/clients/" + cls.client_ids[actor] + "/service-account-user",
                    )["id"],
                )
            cls.installation_observation.update(
                {
                    "actualForeignDenyVerified": True,
                    "actualDeletedDenyVerified": True,
                    "fivePreparedClientsDisabledWithLinksRetained": True,
                }
            )
        elif cls.case == "missing-required-client":
            helper.admin("DELETE", "/clients/" + cls.client_ids["MAIL"])
            helper.assertEqual(
                [], helper.admin("GET", "/clients?clientId=backend-mail")
            )
        elif cls.case == "missing-required-service-account":
            helper.admin("DELETE", "/users/" + SUBJECTS["MAIL"])
            helper.assertEqual(
                1, len(helper.admin("GET", "/clients?clientId=backend-mail"))
            )
            helper.assertEqual(
                404,
                call(
                    cls.base,
                    "GET",
                    "/admin/realms/" + protected.REALM + "/users/" + SUBJECTS["MAIL"],
                    token=cls.installer,
                )[0],
            )
        elif cls.case in {
            "unregistered-technical-human",
            "unregistered-task-role-human",
            "unregistered-inherited-task-human",
        }:
            helper.admin(
                "POST",
                "/users",
                {"username": "unregistered-technical", "enabled": False},
            )
            technical = helper.admin(
                "GET", "/users?username=unregistered-technical&exact=true"
            )
            helper.assertEqual(1, len(technical))
            technical = technical[0]["id"]
            helper.assertNotIn(technical, configuration["technicalSubjects"])
            task = helper.admin("GET", "/roles/invitation-reservations")
            if cls.case == "unregistered-task-role-human":
                helper.admin(
                    "POST", "/users/" + technical + "/role-mappings/realm", [task]
                )
                helper.assertIn(
                    task["id"],
                    {
                        r["id"]
                        for r in helper.admin(
                            "GET", "/users/" + technical + "/role-mappings/realm"
                        )
                    },
                )
            else:
                if cls.case == "unregistered-inherited-task-human":
                    helper.admin(
                        "POST", "/roles", {"name": "technical-parent-composite"}
                    )
                    helper.admin(
                        "POST", "/roles/technical-parent-composite/composites", [task]
                    )
                    parent_role = helper.admin(
                        "GET", "/roles/technical-parent-composite"
                    )
                    helper.assertTrue(parent_role["composite"])
                    helper.assertIn(
                        task["id"],
                        {
                            r["id"]
                            for r in helper.admin(
                                "GET",
                                "/roles/technical-parent-composite/composites/realm",
                            )
                        },
                    )
                    helper.admin("POST", "/groups", {"name": "technical-carrier"})
                    parent = helper.group_id("/technical-carrier")
                    helper.admin(
                        "POST",
                        "/groups/" + parent + "/role-mappings/realm",
                        [parent_role],
                    )
                    helper.admin(
                        "POST",
                        "/groups/" + parent + "/children",
                        {"name": "descendant"},
                    )
                    group = helper.group_id("/technical-carrier/descendant")
                    helper.assertEqual(
                        parent, helper.admin("GET", "/groups/" + group)["parentId"]
                    )
                    helper.assertEqual(
                        [parent_role["id"]],
                        [
                            r["id"]
                            for r in helper.admin(
                                "GET", "/groups/" + parent + "/role-mappings/realm"
                            )
                        ],
                    )
                else:
                    group = helper.group_id("/protected-admins/technical-identities")
                helper.admin("PUT", "/users/" + technical + "/groups/" + group)
                helper.assertEqual(
                    [group],
                    [
                        g["id"]
                        for g in helper.admin("GET", "/users/" + technical + "/groups")
                    ],
                )
        elif cls.case == "allowlisted-denied-human":
            configuration["technicalSubjects"] = sorted(
                configuration["technicalSubjects"] + [protected.HUMAN]
            )
            helper.assertEqual(protected.HUMAN, configuration["bindings"][0]["subject"])
        else:
            raise AssertionError("Unknown fixed installation case")
        cls.mutation_verified = True
        cls.installation_observation["exactNativeMutationVerified"] = True
        return configuration

    @classmethod
    def ready(cls):
        try:
            super().ready()
        except AssertionError as error:
            if (
                cls.phase != "configured-native-restart"
                or str(error) != "Protected owned container exited before readiness"
            ):
                raise
            state = subprocess.run(
                ["docker", "inspect", "--format", "{{json .State}}", cls.name],
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
            state = json.loads(state.stdout)
            if state["Running"] or state["ExitCode"] == 0 or state["OOMKilled"]:
                raise AssertionError("Native installation refusal not proved")
            # Inspect native output in immediate memory only. Persist only the
            # finite stage and booleans; no raw exceptions/config/tokens/logs.
            output = subprocess.run(
                ["docker", "logs", cls.name], capture_output=True, text=True, timeout=30
            )
            native_output = output.stdout + output.stderr
            stage = None
            if (
                "CurrentNativeHumanIdentity.validateInstallation(" in native_output
                and "jakarta.ws.rs.ForbiddenException" in native_output
            ):
                stage = "CURRENT_NATIVE_INSTALLATION_VALIDATION"
            elif (
                "CurrentHumanAuthorization$Policy.<init>(" in native_output
                and "jakarta.ws.rs.BadRequestException" in native_output
            ):
                stage = "HUMAN_TECHNICAL_OVERLAP_CONFIGURATION"
            if stage is None:
                raise AssertionError(
                    "Unrelated native startup error cannot prove installation refusal"
                )
            cls.installation_refused = True
            cls.installation_observation.update(
                {
                    "startupRefused": True,
                    "refusalStage": stage,
                    "nonzeroExitWithoutOom": True,
                }
            )
            image = subprocess.run(
                ["docker", "inspect", "--format", "{{.Image}}", cls.name],
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            ).stdout.strip()
            if not image.startswith("sha256:") or len(image) != 71:
                raise AssertionError("Actual refused native image missing")
            cls.native_image_ids.append(image)

    def test_native_installation_enforces_complete_deny_inventory(self):
        self.assertTrue(self.mutation_verified)
        self.assertTrue(self.configuration_checked)
        self.assertEqual(1, len(self.preconditions))
        if self.case == "extra-denies-prepared-five":
            self.assertFalse(self.installation_refused)
            bearer = self.human(record=False)
            before = self.admin("GET", "/users/count")
            status, value = call(
                self.base,
                "PUT",
                self.endpoint(str(uuid.uuid4())),
                {"scope": self.scope()},
                bearer,
            )
            self.assertEqual(201, status)
            self.assertEqual("AUTHORIZED", value["state"])
            self.assertEqual(before, self.admin("GET", "/users/count"))
            self.installation_observation.update(
                {"actualHumanApproveStatus": status, "noAccountCreated": True}
            )
        elif self.case == "allowlisted-denied-human":
            # Invalid overlap is still rejected by strict init construction.
            self.assertTrue(self.installation_refused)
        else:
            # Native binding failures isolate this configured provider. Human
            # login/userinfo must work, while every approval stays unavailable.
            self.assertFalse(self.installation_refused)
            bearer = self.human(record=False)
            before = self.admin("GET", "/users/count")
            try:
                response = urlopen(
                    Request(
                        self.base + self.endpoint(str(uuid.uuid4())),
                        method="PUT",
                        data=json.dumps({"scope": self.scope()}).encode(),
                        headers={
                            "Content-Type": "application/json",
                            "Authorization": "Bearer " + bearer,
                        },
                    ),
                    timeout=30,
                )
            except HTTPError as error:
                response = error
            with response:
                status = response.code
                no_store = "no-store" in {
                    value.strip().lower()
                    for value in response.headers.get("Cache-Control", "").split(",")
                }
                response.read()
            self.installation_observation.update(
                {
                    "actualHumanNativeLoginAndUserinfoVerified": True,
                    "protectedUnavailableStatus": status,
                    "protectedUnavailableNoStore": no_store,
                }
            )
            self.assertEqual(503, status)
            self.assertTrue(no_store)
            self.assertEqual(before, self.admin("GET", "/users/count"))
            self.installation_observation["noAccountCreated"] = True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--case", required=True, choices=CASES)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    report = Path(args.report).resolve()
    report.parent.mkdir(parents=True, exist_ok=True)
    module = Path(__file__).resolve().parent.parent
    workflow = module.parent.parent / ".github/workflows/scenario-c-protected-proof.yml"
    jar = Path(os.environ.get("LIFECYCLE_C_TEST_JAR", ""))
    before, workflow_before = source_manifest(module), digest(workflow)
    summary = {
        "schema": 1,
        "suite": "protected-native-installation",
        "case": args.case,
        "classification": "INPUT_OR_FIXTURE_ERROR",
        "sourceManifest": before,
        "workflowSHA256": workflow_before,
        "gitRevision": os.environ.get("GITHUB_SHA"),
        "keycloakImageIndex": IMAGE,
        "executed": 0,
        "failures": 0,
        "errors": 0,
        "skipped": 0,
    }
    result = None
    started = time.monotonic()
    try:
        if not jar.is_file():
            raise AssertionError("Actual packaged JAR required")
        summary["jarSHA256"] = digest(jar)
        summary["unitEvidence"] = unit_evidence(module / "target/surefire-reports")
        Installation.case = args.case
        suite = unittest.TestSuite(
            [Installation("test_native_installation_enforces_complete_deny_inventory")]
        )

        def deadline(signum, frame):
            raise ProofDeadlineReached("Finite600s native proof deadline")

        previous = signal.signal(signal.SIGALRM, deadline)
        signal.setitimer(signal.ITIMER_REAL, 600)
        try:
            result = SanitizedResult()
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
                io.StringIO()
            ):
                suite.run(result)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)
        summary.update(
            {
                "executed": result.testsRun,
                "failures": len(result.failures),
                "errors": len(result.errors),
                "skipped": len(result.skipped),
                "cases": {
                    key: {k: v for k, v in val.items() if k != "started"}
                    for key, val in result.cases.items()
                },
                "nativeHumanPreconditions": getattr(Installation, "preconditions", []),
                "nativeImageIds": getattr(Installation, "native_image_ids", []),
                "installationObservation": getattr(
                    Installation, "installation_observation", {}
                ),
                "configurationChecked": getattr(
                    Installation, "configuration_checked", False
                ),
                "phase": getattr(Installation, "phase", "not-started"),
            }
        )
        valid = (
            summary["configurationChecked"]
            and len(summary["nativeHumanPreconditions"]) == 1
            and summary["nativeHumanPreconditions"][0]["nativeUserinfoValidatedToken"]
            and summary["nativeHumanPreconditions"][0]["currentNativeSession"]
            and len(summary["nativeImageIds"]) == 2
            and len(set(summary["nativeImageIds"])) == 1
            and summary["installationObservation"].get("exactNativeMutationVerified")
            is True
            and summary["installationObservation"].get(
                "allFiveCurrentNativeClientLinksVerified"
            )
            is True
        )
        if valid and result.testsRun == 1 and not result.errors and not result.skipped:
            if result.wasSuccessful():
                summary["classification"] = "GREEN"
            elif (
                summary["installationObservation"].get(
                    "actualHumanNativeLoginAndUserinfoVerified"
                )
                is True
                and summary["installationObservation"].get("protectedUnavailableStatus")
                == 503
                and summary["installationObservation"].get(
                    "protectedUnavailableNoStore"
                )
                is False
            ):
                summary["classification"] = "GENUINE_PROTECTED_UNAVAILABLE_NO_STORE_RED"
            elif (
                args.case == "extra-denies-prepared-five"
                and summary["installationObservation"].get("refusalStage")
                == "CURRENT_NATIVE_INSTALLATION_VALIDATION"
            ):
                summary["classification"] = "GENUINE_DENY_EXTRAS_INSTALLATION_RED"
            elif (
                args.case
                in {
                    "unregistered-technical-human",
                    "unregistered-task-role-human",
                    "unregistered-inherited-task-human",
                }
                and summary["installationObservation"].get("protectedUnavailableStatus")
                == 201
            ):
                summary["classification"] = "GENUINE_MISSING_TECHNICAL_COVERAGE_RED"
            else:
                summary["classification"] = "BEHAVIOR_FAILURE"
    except Exception as error:
        summary["gateErrorType"] = type(error).__name__
        summary["errors"] = max(1, summary["errors"])
    finally:
        try:
            summary["cleanup"] = cleanup_owned(Installation)
        except Exception as error:
            summary["cleanup"] = {"errorType": type(error).__name__}
            summary["classification"] = "CLEANUP_UNVERIFIED"
        summary["resourceEvidence"] = resource_evidence()
        summary["sourceStable"] = before == source_manifest(module)
        summary["workflowStable"] = workflow_before == digest(workflow)
        summary["jarStable"] = jar.is_file() and summary.get("jarSHA256") == digest(jar)
        if not all(
            summary[key] for key in ("sourceStable", "workflowStable", "jarStable")
        ):
            summary["classification"] = "INPUT_CHANGED_OR_MISSING"
        summary["durationSeconds"] = round(time.monotonic() - started, 3)
        write_xml(report.with_suffix(".xml"), result, summary["classification"])
        report.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(
        json.dumps(
            {
                k: summary[k]
                for k in (
                    "case",
                    "classification",
                    "executed",
                    "failures",
                    "errors",
                    "skipped",
                )
            }
        )
    )
    return 0 if summary["classification"] == "GREEN" else 1


if __name__ == "__main__":
    raise SystemExit(main())
