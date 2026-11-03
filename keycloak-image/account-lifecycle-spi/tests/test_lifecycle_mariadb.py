#!/usr/bin/env python3
"""Actual MariaDB, two receiver replicas, atomic failure and durable receipts."""

import copy
from concurrent.futures import ThreadPoolExecutor
import subprocess
import unittest
import uuid
from mariadb_fixture import MariaDbFixture
from lifecycle_fixture import REALM, call, mac
import time


class MariaDbLifecycleProof(MariaDbFixture, unittest.TestCase):
    def on_node(self, index, command, attempt, body, bearer=None):
        client = copy.copy(self)
        client.base = self.bases[index]
        return client.request(command, attempt, body, bearer=bearer)

    def test_before_lock_committed_role_drift_denies_compensation_and_commit(self):
        self.before_lock_drift_cases(("role",))

    def test_before_lock_committed_child_drift_denies_read_commit_and_cleanup(self):
        self.before_lock_drift_cases(
            (
                "group",
                "attribute",
                "long-attribute",
                "action",
                "credential",
                "credential-label",
            )
        )

    def attempt_digest(self, attempt):
        columns = self.sql(
            "SELECT COLUMN_NAME FROM information_schema.COLUMNS WHERE TABLE_SCHEMA='keycloak' AND TABLE_NAME='ORISO_ACCOUNT_LIFECYCLE_ATTEMPT' ORDER BY ORDINAL_POSITION"
        ).splitlines()
        expression = ",".join(
            "COALESCE(CAST(" + column + " AS CHAR),'<NULL>')" for column in columns
        )
        return self.sql(
            "SELECT SHA2(JSON_ARRAY("
            + expression
            + "),256) FROM ORISO_ACCOUNT_LIFECYCLE_ATTEMPT WHERE ATTEMPT_ID='"
            + attempt
            + "'"
        )

    def before_lock_drift_cases(self, edits):
        profile = self.admin("GET", "/users/profile")
        profile["unmanagedAttributePolicy"] = "ENABLED"
        self.admin("PUT", "/users/profile", profile)
        for edit in edits:
            for command, recovered in (
                ("compensate", False),
                ("commit", False),
                ("compensate", True),
                ("owned-read", False),
            ):
                with self.subTest(edit=edit, command=command, recovered=recovered):
                    attempt, create = str(uuid.uuid4()), self.creation()
                    status, opened = self.on_node(0, "create", attempt, create)
                    self.assertEqual(201, status)
                    if recovered:
                        recovery = {
                            "identity": create["identity"],
                            "expectedGeneration": 0,
                            "recoveryId": str(uuid.uuid4()),
                        }
                        status, opened = self.on_node(0, "recover", attempt, recovery)
                        self.assertEqual(200, status)
                    user = opened["accountId"]
                    role = self.admin("GET", "/roles/tenant-admin")
                    extra_group = self.group_id("/human-roles/agency-admin")
                    credential = self.admin("GET", "/users/" + user + "/credentials")[
                        0
                    ]["id"]
                    credential_before = self.sql(
                        "SELECT SHA2(CREDENTIAL_DATA,256) FROM CREDENTIAL WHERE USER_ID='"
                        + user
                        + "'"
                    )
                    statements = {
                        "role": "INSERT INTO USER_ROLE_MAPPING (USER_ID,ROLE_ID) VALUES ('"
                        + user
                        + "','"
                        + role["id"]
                        + "')",
                        "group": "INSERT INTO USER_GROUP_MEMBERSHIP (USER_ID,GROUP_ID,MEMBERSHIP_TYPE) VALUES ('"
                        + user
                        + "','"
                        + extra_group
                        + "','UNMANAGED')",
                        "attribute": "UPDATE USER_ATTRIBUTE SET VALUE='99' WHERE USER_ID='"
                        + user
                        + "' AND NAME='tenantId'",
                        "long-attribute": "UPDATE USER_ATTRIBUTE SET VALUE=NULL,LONG_VALUE='"
                        + ("l" * 600)
                        + "' WHERE USER_ID='"
                        + user
                        + "' AND NAME='tenantId'",
                        "action": "INSERT INTO USER_REQUIRED_ACTION (USER_ID,REQUIRED_ACTION) VALUES ('"
                        + user
                        + "','UPDATE_PASSWORD')",
                        "credential": "UPDATE CREDENTIAL SET CREDENTIAL_DATA=CONCAT(CREDENTIAL_DATA,' ') WHERE USER_ID='"
                        + user
                        + "'",
                        "credential-label": "UPDATE CREDENTIAL SET USER_LABEL='Installer changed' WHERE USER_ID='"
                        + user
                        + "'",
                    }
                    before = self.attempt_digest(attempt)
                    body = self.finish(create, opened, cleanup=command == "compensate")
                    if command == "owned-read":
                        body.pop("localCommit")
                    token = self.token()
                    self.admin("POST", "/clear-user-cache")
                    editor = self.start_locked_user_editor(user)
                    try:
                        with ThreadPoolExecutor(max_workers=1) as workers:
                            request = workers.submit(
                                self.on_node, 1, command, attempt, body, token
                            )
                            self.wait_for_receiver_user_lock_and_read_view(user)
                            self.commit_locked_editor(editor, statements[edit])
                            status, result = request.result()
                        present = self.sql(
                            "SELECT COUNT(*) FROM USER_ENTITY WHERE ID='" + user + "'"
                        )
                        state = self.sql(
                            "SELECT STATE FROM ORISO_ACCOUNT_LIFECYCLE_ATTEMPT WHERE ATTEMPT_ID='"
                            + attempt
                            + "'"
                        )
                        print(
                            "Before-lock drift result:",
                            {
                                "edit": edit,
                                "command": command,
                                "recovered": recovered,
                                "status": status,
                                "userPresent": present == "1",
                                "state": state,
                                "receiverIsolation": "REPEATABLE READ",
                                "receiverReadView": True,
                            },
                        )
                        self.assertEqual(409, status)
                        self.assertEqual("1", present)
                        self.assertEqual(before, self.attempt_digest(attempt))
                        self.admin("POST", "/clear-user-cache")
                        actual = self.admin("GET", "/users/" + user)
                        self.assertFalse(actual["enabled"])
                        groups = self.admin("GET", "/users/" + user + "/groups")
                        self.assertIn(
                            "pending-provisioning", {group["name"] for group in groups}
                        )
                        if edit == "role":
                            roles = self.admin(
                                "GET", "/users/" + user + "/role-mappings/realm"
                            )
                            self.assertIn(
                                "tenant-admin", {entry["name"] for entry in roles}
                            )
                        elif edit == "group":
                            self.assertIn(
                                extra_group, {entry["id"] for entry in groups}
                            )
                        elif edit == "attribute":
                            self.assertEqual(["99"], actual["attributes"]["tenantId"])
                        elif edit == "long-attribute":
                            self.assertEqual(
                                ["l" * 600], actual["attributes"]["tenantId"]
                            )
                        elif edit == "action":
                            self.assertIn("UPDATE_PASSWORD", actual["requiredActions"])
                        else:
                            credentials = self.admin(
                                "GET", "/users/" + user + "/credentials"
                            )
                            self.assertEqual(
                                [credential], [entry["id"] for entry in credentials]
                            )
                            if edit == "credential-label":
                                self.assertEqual(
                                    "Installer changed", credentials[0]["userLabel"]
                                )
                            else:
                                self.assertNotEqual(
                                    credential_before,
                                    self.sql(
                                        "SELECT SHA2(CREDENTIAL_DATA,256) FROM CREDENTIAL WHERE USER_ID='"
                                        + user
                                        + "'"
                                    ),
                                )
                    finally:
                        self.stop_locked_editor(editor)

    def test_removed_snapshot_membership_cannot_commit_without_approved_group(self):
        attempt, create = str(uuid.uuid4()), self.creation()
        status, opened = self.on_node(0, "create", attempt, create)
        self.assertEqual(201, status)
        user = opened["accountId"]
        approved = self.group_id("/human-roles/consultant")
        pending = self.group_id("/pending-provisioning")
        self.admin("PUT", "/users/" + user + "/groups/" + approved)
        groups = self.admin("GET", "/users/" + user + "/groups")
        self.assertEqual({pending, approved}, {group["id"] for group in groups})
        self.assertFalse(self.admin("GET", "/users/" + user)["enabled"])
        before = self.attempt_digest(attempt)
        body = self.finish(create, opened)
        token = self.token()
        self.admin("POST", "/clear-user-cache")
        editor = self.start_locked_user_editor(user)
        try:
            with ThreadPoolExecutor(max_workers=1) as workers:
                request = workers.submit(
                    self.on_node, 1, "commit", attempt, body, token
                )
                self.wait_for_receiver_user_lock_and_read_view(user)
                self.commit_locked_editor(
                    editor,
                    "DELETE FROM USER_GROUP_MEMBERSHIP WHERE USER_ID='"
                    + user
                    + "' AND GROUP_ID='"
                    + approved
                    + "'",
                )
                status, result = request.result()
            self.admin("POST", "/clear-user-cache")
            current = self.admin("GET", "/users/" + user)
            current_groups = {
                group["id"] for group in self.admin("GET", "/users/" + user + "/groups")
            }
            state = self.sql(
                "SELECT STATE FROM ORISO_ACCOUNT_LIFECYCLE_ATTEMPT WHERE ATTEMPT_ID='"
                + attempt
                + "'"
            )
            print(
                "Inverse-membership result:",
                {
                    "status": status,
                    "enabled": current["enabled"],
                    "pendingRetained": pending in current_groups,
                    "approvedRetained": approved in current_groups,
                    "groupCount": len(current_groups),
                    "state": state,
                    "receiverIsolation": "REPEATABLE READ",
                    "receiverReadView": True,
                },
            )
            self.assertEqual(409, status)
            self.assertFalse(current["enabled"])
            self.assertEqual({pending}, current_groups)
            self.assertEqual(before, self.attempt_digest(attempt))
            self.assertEqual(200, self.on_node(0, "commit", attempt, body, token)[0])
            self.admin("POST", "/clear-user-cache")
            self.assertTrue(self.admin("GET", "/users/" + user)["enabled"])
            self.assertEqual(
                {approved},
                {
                    group["id"]
                    for group in self.admin("GET", "/users/" + user + "/groups")
                },
            )
        finally:
            self.stop_locked_editor(editor)

    def test_two_replicas_create_same_attempt_once(self):
        attempt, create = str(uuid.uuid4()), self.creation()
        token = self.token()
        with ThreadPoolExecutor(max_workers=2) as workers:
            results = [
                workers.submit(self.on_node, node, "create", attempt, create, token)
                for node in range(2)
            ]
            outcomes = [future.result() for future in results]
        self.assertEqual([200, 201], sorted(status for status, _ in outcomes))
        self.assertEqual(outcomes[0][1], outcomes[1][1])
        count = self.sql(
            "SELECT COUNT(*) FROM USER_ENTITY WHERE USERNAME='"
            + create["account"]["username"]
            + "'"
        )
        self.assertEqual("1", count)
        self.assertFalse(
            self.admin("GET", "/users/" + outcomes[0][1]["accountId"])["enabled"]
        )

    def test_two_replicas_absent_recovery_serializes_delayed_creation(self):
        attempt, create = str(uuid.uuid4()), self.creation()
        recovery = {
            "identity": create["identity"],
            "expectedGeneration": 0,
            "recoveryId": str(uuid.uuid4()),
        }
        token = self.token()
        with ThreadPoolExecutor(max_workers=2) as workers:
            a = workers.submit(self.on_node, 0, "create", attempt, create, token)
            b = workers.submit(self.on_node, 1, "recover", attempt, recovery, token)
            first, recovered = a.result(), b.result()
        self.assertIn(first[0], (201, 409))
        self.assertEqual(200, recovered[0])
        self.assertIn(recovered[1]["state"], ("RECOVERY_CLAIMED", "ABANDONED"))
        self.assertEqual(409, self.on_node(0, "create", attempt, create)[0])
        self.assertEqual(409, self.on_node(1, "create", attempt, create)[0])

    def test_mariadb_commit_failure_rolls_back_membership_activation_and_attempt(self):
        attempt, create = str(uuid.uuid4()), self.creation()
        status, opened = self.on_node(0, "create", attempt, create)
        self.assertEqual(201, status)
        username = create["account"]["username"]
        self.sql(
            "CREATE TRIGGER reject_lifecycle_activation BEFORE UPDATE ON USER_ENTITY FOR EACH ROW BEGIN IF NEW.USERNAME='"
            + username
            + "' AND NEW.ENABLED=1 THEN SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='synthetic activation failure'; END IF; END"
        )
        try:
            self.assertIn(
                self.on_node(1, "commit", attempt, self.finish(create, opened))[0],
                (500, 503),
            )
        finally:
            self.sql("DROP TRIGGER reject_lifecycle_activation")
        self.assertEqual(
            "OPEN",
            self.sql(
                "SELECT STATE FROM ORISO_ACCOUNT_LIFECYCLE_ATTEMPT WHERE ATTEMPT_ID='"
                + attempt
                + "'"
            ),
        )
        self.assertFalse(self.admin("GET", "/users/" + opened["accountId"])["enabled"])
        self.assertEqual(
            "1",
            self.sql(
                "SELECT COUNT(*) FROM ADMIN_EVENT_ENTITY WHERE RESOURCE_PATH='accounts/"
                + opened["accountId"]
                + "'"
            ),
        )
        self.assertEqual(
            ["/pending-provisioning"],
            [
                g["path"]
                for g in self.admin("GET", "/users/" + opened["accountId"] + "/groups")
            ],
        )
        self.assertEqual(
            200, self.on_node(0, "commit", attempt, self.finish(create, opened))[0]
        )

    def test_two_replicas_terminal_race_and_database_restart_preserve_receipts(self):
        attempt, create = str(uuid.uuid4()), self.creation()
        status, opened = self.on_node(0, "create", attempt, create)
        self.assertEqual(201, status)
        commit, cleanup = self.finish(create, opened), self.finish(
            create, opened, cleanup=True
        )
        token = self.token()
        with ThreadPoolExecutor(max_workers=2) as workers:
            a = workers.submit(self.on_node, 0, "commit", attempt, commit, token)
            b = workers.submit(self.on_node, 1, "compensate", attempt, cleanup, token)
            outcomes = [a.result(), b.result()]
        self.assertEqual([200, 409], sorted(status for status, _ in outcomes))
        winner = next(body for status, body in outcomes if status == 200)
        command, body = (
            ("commit", commit)
            if winner["state"] == "COMMITTED"
            else ("compensate", cleanup)
        )
        subprocess.run(
            ["docker", "restart", self.database], check=True, capture_output=True
        )
        # Both pooled receivers must recover after an actual database restart.
        import time

        deadline = time.monotonic() + 90
        while True:
            # Reuse the authenticated actor across actual DB downtime. Minting a
            # new token here would fail in fixture setup before testing recovery.
            status, repeated = self.on_node(1, command, attempt, body, bearer=token)
            if status == 200:
                break
            if time.monotonic() > deadline:
                self.fail("Owned MariaDB restart recovery did not complete")
            time.sleep(1)
        self.assertEqual(winner["terminalReceipt"], repeated["terminalReceipt"])
        self.assertEqual(winner["execution"], repeated["execution"])

    def test_pending_group_privilege_edits_wait_for_guarded_cleanup_transaction(self):
        group = self.group_id("/pending-provisioning")
        role = self.admin("GET", "/roles/consultant")
        path = "/admin/realms/" + REALM + "/groups/" + group + "/role-mappings/realm"
        # Warm the exact native route on the second replica before the SQL latch.
        self.assertEqual(
            204, call(self.bases[1], "POST", path, [role], self.installer)[0]
        )
        self.assertEqual(
            204, call(self.bases[1], "DELETE", path, [role], self.installer)[0]
        )
        self.admin("PUT", "", {"adminEventsEnabled": False})
        status, current = call(
            self.bases[1], "GET", "/admin/realms/" + REALM, token=self.installer
        )
        self.assertEqual(200, status)
        self.assertFalse(
            current["adminEventsEnabled"],
            "Optional auditing must not incidentally provide this security fence",
        )
        attempt, create = str(uuid.uuid4()), self.creation()
        status, opened = self.on_node(0, "create", attempt, create)
        self.assertEqual(201, status)
        marker = "lifecycle-group-delete-" + uuid.uuid4().hex
        username = create["account"]["username"]
        self.sql(
            "CREATE TRIGGER pause_lifecycle_delete BEFORE DELETE ON USER_ENTITY FOR EACH ROW BEGIN IF OLD.USERNAME='"
            + username
            + "' THEN DO GET_LOCK('"
            + marker
            + "', 0); DO SLEEP(8); DO RELEASE_LOCK('"
            + marker
            + "'); END IF; END"
        )
        token = self.token()
        escaped = blocked = False
        try:
            with ThreadPoolExecutor(max_workers=2) as workers:
                cleanup = workers.submit(
                    self.on_node,
                    0,
                    "compensate",
                    attempt,
                    self.finish(create, opened, cleanup=True),
                    token,
                )
                deadline = time.monotonic() + 10
                while self.sql("SELECT IS_USED_LOCK('" + marker + "')") == "NULL":
                    if time.monotonic() > deadline:
                        self.fail("Cleanup did not reach actual guarded SQL deletion")
                    time.sleep(0.05)
                grant = workers.submit(
                    call, self.bases[1], "POST", path, [role], self.installer
                )
                deadline = time.monotonic() + 6
                while time.monotonic() < deadline:
                    mapping = self.sql(
                        "SELECT COUNT(*) FROM GROUP_ROLE_MAPPING WHERE GROUP_ID='"
                        + group
                        + "' AND ROLE_ID='"
                        + role["id"]
                        + "'"
                    )
                    if mapping == "1":
                        self.assertNotEqual(
                            "NULL", self.sql("SELECT IS_USED_LOCK('" + marker + "')")
                        )
                        escaped = True
                        break
                    waits = self.sql(
                        "SELECT COUNT(*) FROM information_schema.INNODB_LOCK_WAITS w JOIN information_schema.INNODB_LOCKS l ON w.requested_lock_id=l.lock_id WHERE l.lock_table LIKE '%KEYCLOAK_GROUP%' OR l.lock_table LIKE '%GROUP_ROLE_MAPPING%' OR l.lock_table LIKE '%REALM%'"
                    )
                    if int(waits) > 0:
                        blocked = True
                        break
                    if cleanup.done():
                        self.fail(
                            "Delete latch ended before the native grant reached a measured database outcome"
                        )
                    time.sleep(0.05)
                self.assertEqual(200, cleanup.result()[0])
                self.assertEqual(204, grant.result()[0])
            read_status, actual_roles = call(
                self.bases[1], "GET", path, token=self.installer
            )
            self.assertEqual(200, read_status)
            self.assertIn("consultant", {entry["name"] for entry in actual_roles})
            self.assertFalse(
                escaped,
                "Actual native grant204 and committed role readback escaped while guarded deletion was paused",
            )
            self.assertTrue(
                blocked,
                "Native grant must reach an observed InnoDB integrity lock; HTTP timing is insufficient",
            )
            self.assertEqual(
                [], self.admin("GET", "/users?username=" + username + "&exact=true")
            )
        finally:
            self.sql("DROP TRIGGER pause_lifecycle_delete")

    def test_installer_edits_cannot_win_after_cleanup_integrity_check(self):
        for edit in ("profile", "attribute", "credential", "action", "group"):
            with self.subTest(edit=edit):
                attempt, create = str(uuid.uuid4()), self.creation()
                if edit == "action":
                    create["account"]["passwordTemporary"] = True
                    create["identity"]["creationFingerprint"] = mac(
                        "creation-payload",
                        {
                            "scope": create["identity"]["scope"],
                            "account": create["account"],
                        },
                    )
                status, opened = self.on_node(0, "create", attempt, create)
                self.assertEqual(201, status)
                username, user = create["account"]["username"], opened["accountId"]
                marker = "lifecycle-delete-" + uuid.uuid4().hex
                self.sql(
                    "CREATE TRIGGER pause_lifecycle_delete BEFORE DELETE ON USER_ENTITY FOR EACH ROW BEGIN IF OLD.USERNAME='"
                    + username
                    + "' THEN DO GET_LOCK('"
                    + marker
                    + "', 0); DO SLEEP(2); DO RELEASE_LOCK('"
                    + marker
                    + "'); END IF; END"
                )
                token = self.token()
                try:
                    with ThreadPoolExecutor(max_workers=2) as workers:
                        cleanup = workers.submit(
                            self.on_node,
                            0,
                            "compensate",
                            attempt,
                            self.finish(create, opened, cleanup=True),
                            token,
                        )
                        deadline = time.monotonic() + 10
                        while (
                            self.sql("SELECT IS_USED_LOCK('" + marker + "')") == "NULL"
                        ):
                            if time.monotonic() > deadline:
                                self.fail(
                                    "Cleanup did not reach actual guarded SQL deletion"
                                )
                            time.sleep(0.05)
                        path, method = (
                            "/admin/realms/" + REALM + "/users/" + user,
                            "PUT",
                        )
                        body = (
                            {"firstName": "Installer raced"}
                            if edit == "profile"
                            else {"attributes": {"locale": ["fr"]}}
                        )
                        if edit == "credential":
                            path += "/reset-password"
                            body = {
                                "type": "password",
                                "value": "Installer-raced-password-0001",
                                "temporary": False,
                            }
                        elif edit == "action":
                            body = {"requiredActions": []}
                        elif edit == "group":
                            path += "/groups/" + self.group_id(
                                "/human-roles/consultant"
                            )
                            body = None
                        edited = workers.submit(
                            call, self.bases[1], method, path, body, self.installer
                        )
                        deleted, changed = cleanup.result(), edited.result()
                    self.assertEqual(200, deleted[0])
                    self.assertNotEqual(
                        204,
                        changed[0],
                        "An installer edit cannot complete after the receiver owns and verifies deletion",
                    )
                    self.assertEqual(
                        [],
                        self.admin(
                            "GET", "/users?username=" + username + "&exact=true"
                        ),
                    )
                finally:
                    self.sql("DROP TRIGGER pause_lifecycle_delete")


if __name__ == "__main__":
    unittest.main(verbosity=2)
