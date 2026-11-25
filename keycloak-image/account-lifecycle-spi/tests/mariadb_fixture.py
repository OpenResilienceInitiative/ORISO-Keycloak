#!/usr/bin/env python3
"""Two isolated, heap-bounded Keycloak replicas sharing one owned MariaDB."""

import hashlib
import json
import os
from pathlib import Path
import subprocess
import time
import uuid
from lifecycle_fixture import (
    LifecycleFixture,
    IMAGE,
    INSTALLER,
    REALM,
    SUBJECTS,
    CONTEXT_KEY,
    HUMAN_GROUPS,
)
import base64
import re
import select

DEFAULT_MARIADB_IMAGE = (
    "mariadb@sha256:1292844148b311e4ed4300022a996d39083f415a963e970cf47cad1b3b18e3a6"
)
COMPAT_MARIADB_IMAGE = (
    "mariadb@sha256:55db5a18b68b5f6db4c04640ad27301c0582cd799880f9ed6d9a458a5795342e"
)
# Explicit amd64 variants for isolated hosted CI; local proof pins remain unchanged.
CI_MARIADB_IMAGE = (
    "mariadb@sha256:33a6653ab666774f48818120045f9367a81cd4c54c027412fe294a7d1274e2dc"
)
CI_COMPAT_MARIADB_IMAGE = (
    "mariadb@sha256:082554e82eb0e333cddd152d474bb55b8155c8f6585d4c5b0fb47ce2f740cb08"
)
MARIADB_IMAGE = os.environ.get("LIFECYCLE_C_MARIADB_TEST_IMAGE", DEFAULT_MARIADB_IMAGE)
if MARIADB_IMAGE not in {
    DEFAULT_MARIADB_IMAGE,
    COMPAT_MARIADB_IMAGE,
    CI_MARIADB_IMAGE,
    CI_COMPAT_MARIADB_IMAGE,
}:
    raise AssertionError("An explicitly approved pinned MariaDB test image is required")


class MariaDbFixture(LifecycleFixture):
    RECEIVER_WAIT_SECONDS = 15
    # InnoDB refreshes its INNODB_TRX / INNODB_LOCKS / INNODB_LOCK_WAITS
    # snapshot only after 100 ms without any read of it. Polling faster keeps
    # the snapshot from before the wait began, so a real lock wait is never
    # seen (reproduced on MariaDB 11.0.6: 0 of 120 polls at 50 ms saw a 6 s
    # wait). Poll these views at least this far apart.
    INNODB_VIEW_POLL_SECONDS = 0.25

    @classmethod
    def setUpClass(cls):
        jar = Path(os.environ.get("LIFECYCLE_C_TEST_JAR", ""))
        if not jar.is_file():
            raise AssertionError(
                "LIFECYCLE_C_TEST_JAR must identify actual packaged provider"
            )
        cls.jar_path = jar.resolve()
        cls.jar_sha256 = hashlib.sha256(cls.jar_path.read_bytes()).hexdigest()
        tag = uuid.uuid4().hex[:10]
        cls.network = "oriso-c-lifecycle-net-" + tag
        cls.database = "oriso-c-lifecycle-db-" + tag
        cls.names = []
        subprocess.run(
            ["docker", "network", "create", cls.network],
            check=True,
            capture_output=True,
        )
        cls.addClassCleanup(cls.stop)
        command = [
            "docker",
            "run",
            "-d",
            "--name",
            cls.database,
            "--network",
            cls.network,
            "--memory",
            "512m",
            "--cpus",
            "2",
            "--label",
            "oriso-c-lifecycle-test=true",
            "-e",
            "MARIADB_ROOT_PASSWORD=synthetic-lifecycle-db-root",
            "-e",
            "MARIADB_DATABASE=keycloak",
            "-e",
            "MARIADB_USER=keycloak",
            "-e",
            "MARIADB_PASSWORD=synthetic-lifecycle-db",
            MARIADB_IMAGE,
            "--innodb-buffer-pool-size=128M",
        ]
        subprocess.run(command, check=True, capture_output=True)
        cls.names.append(cls.database)
        deadline = time.monotonic() + 120
        while True:
            result = subprocess.run(
                [
                    "docker",
                    "exec",
                    "-e",
                    "MYSQL_PWD=synthetic-lifecycle-db-root",
                    cls.database,
                    "mariadb",
                    "-uroot",
                    "-N",
                    "-e",
                    "SELECT VERSION(), @@tx_isolation",
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                cls.database_version, cls.database_isolation = (
                    result.stdout.strip().split("\t")
                )
                break
            if time.monotonic() > deadline:
                raise AssertionError("Owned MariaDB readiness failed")
            time.sleep(1)
        cls.bases = []
        for index in range(2):
            name = "oriso-c-lifecycle-kc-" + tag + "-" + str(index)
            command = [
                "docker",
                "run",
                "-d",
                "--name",
                name,
                "--network",
                cls.network,
                "--memory",
                "1g",
                "--cpus",
                "2",
                "--label",
                "oriso-c-lifecycle-test=true",
                "-p",
                "127.0.0.1::8080",
                "-e",
                "JAVA_OPTS_APPEND=-Xms128m -Xmx512m -XX:ActiveProcessorCount=2",
                "-e",
                "KC_BOOTSTRAP_ADMIN_USERNAME=synthetic-installer", "-e", "KC_SPI_ADMIN__AUDIENCE_CHECK_ENABLED=false",  # Same as the ORISO image (Keycloak#78).
                "-e",
                "KC_BOOTSTRAP_ADMIN_PASSWORD=" + INSTALLER,
                "-e",
                "KC_HOSTNAME=http://lifecycle-fixture.invalid",
                "-e",
                "KC_DB=mariadb",
                "-e",
                "KC_DB_URL=jdbc:mariadb://" + cls.database + ":3306/keycloak",
                "-e",
                "KC_DB_USERNAME=keycloak",
                "-e",
                "KC_DB_PASSWORD=synthetic-lifecycle-db",
                "-e",
                "KC_DB_POOL_INITIAL_SIZE=1",
                "-e",
                "KC_DB_POOL_MIN_SIZE=1",
                "-e",
                "KC_DB_POOL_MAX_SIZE=5",
                "-e",
                "TASK_IDENTITY_MODEL=FIVE_ACTORS",
                "-e",
                "ORISO_ACCOUNT_LIFECYCLE_ENABLED=true",
                "-e",
                "ORISO_ACCOUNT_LIFECYCLE_REALM=" + REALM,
                "-e",
                "IDENTITY_ACCOUNT_CREATE_SERVICE_SUBJECT=" + SUBJECTS["ACCOUNT_CREATE"],
                "-e",
                "IDENTITY_ACCOUNT_ADMIN_SERVICE_SUBJECT=" + SUBJECTS["ACCOUNT_ADMIN"],
                "-e",
                "ORISO_TASK_CONTEXT_KEY=" + base64.b64encode(CONTEXT_KEY).decode(),
                "-e",
                "ORISO_IDENTITY_DUMMY_EMAIL_SUFFIX=@lifecycle-fixture.invalid",
                "-e",
                "ORISO_ACCOUNT_LIFECYCLE_GROUPS="
                + json.dumps(
                    {"/human-roles/" + k: v for k, v in HUMAN_GROUPS.items()},
                    separators=(",", ":"),
                ),
                "-v",
                str(jar.resolve())
                + ":/opt/keycloak/providers/account-lifecycle-spi.jar:ro",
                IMAGE,
                "start-dev",
                "--cache=ispn",
                "--cache-stack=jdbc-ping",
            ]
            subprocess.run(command, check=True, capture_output=True)
            cls.names.append(name)
            if hashlib.sha256(cls.jar_path.read_bytes()).hexdigest() != cls.jar_sha256:
                raise AssertionError("Native provider changed during replica bind")
            endpoint = (
                subprocess.check_output(["docker", "port", name, "8080/tcp"], text=True)
                .strip()
                .splitlines()[0]
            )
            cls.base = "http://" + endpoint
            cls.name = name
            cls.bases.append(cls.base)
            cls.ready()
        cls.base = cls.bases[0]
        cls.name = cls.names[1]
        cls.ready()

    @classmethod
    def stop(cls):
        private = os.environ.get("LIFECYCLE_C_PRIVATE_LOG_DIR")
        for name in reversed(cls.names):
            if private:
                folder = Path(private)
                if folder.is_dir() and folder.stat().st_mode & 0o077 == 0:
                    log = folder / (name + ".log")
                    with log.open("wb") as output:
                        log.chmod(0o600)
                        subprocess.run(
                            ["docker", "logs", name],
                            stdout=output,
                            stderr=subprocess.STDOUT,
                            check=False,
                        )
            subprocess.run(
                ["docker", "rm", "-f", name], check=True, capture_output=True
            )
        subprocess.run(
            ["docker", "network", "rm", cls.network], check=True, capture_output=True
        )
        print("MariaDB patch version:", getattr(cls, "database_version", "NOT_READY"))
        print(
            "MariaDB transaction isolation:",
            getattr(cls, "database_isolation", "NOT_READY"),
        )
        if hashlib.sha256(cls.jar_path.read_bytes()).hexdigest() != cls.jar_sha256:
            raise AssertionError("Native provider changed during replica execution")
        print("Lifecycle provider jar sha256:", cls.jar_sha256)

    def setUp(self):
        # Confirm both replicas still answer before each test. The installer token
        # itself is renewed on use (LifecycleFixture.installer), because a single
        # method with many subtests outlives the 60-second master token.
        type(self).ready()
        super().setUp()

    def sql(self, statement):
        result = subprocess.run(
            [
                "docker",
                "exec",
                "-e",
                "MYSQL_PWD=synthetic-lifecycle-db-root",
                self.database,
                "mariadb",
                "-uroot",
                "-N",
                "--delimiter=//",
                "keycloak",
                "-e",
                statement + "//",
            ],
            capture_output=True,
            text=True,
        )
        codes = re.findall(r"ERROR (\d+) \(([A-Z0-9]+)\)", result.stderr)
        self.assertEqual(
            0, result.returncode, "Owned fixture SQL failed: " + repr(codes)
        )
        return result.stdout.strip()

    def start_locked_user_editor(self, user):
        # Persistent stdin provides an actual database latch without timing sleeps.
        command = [
            "docker",
            "exec",
            "-i",
            "-e",
            "MYSQL_PWD=synthetic-lifecycle-db-root",
            self.database,
            "mariadb",
            "-uroot",
            "-N",
            "--batch",
            "--unbuffered",
            "--delimiter=//",
            "keycloak",
        ]
        editor = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self.addCleanup(self.stop_locked_editor, editor)
        # One output line per marker: select() only sees unread pipe data, so a
        # second line already pulled into readline()'s buffer would time out.
        editor.stdin.write(
            "START TRANSACTION//\nSELECT ID INTO @held_user FROM USER_ENTITY WHERE ID='"
            + user
            + "' FOR UPDATE//\nSELECT CONCAT('USER_LOCK_HELD ', CONNECTION_ID())//\n"
        )
        editor.stdin.flush()
        holder = self.lock_holder(self.editor_line(editor))
        # The witness recognises the receiver's wait by this lock holder too:
        # MariaDB does not always report the locked row's key in lock_data.
        self.user_lock_holders = {
            **getattr(self, "user_lock_holders", {}),
            user: holder,
        }
        return editor

    def lock_holder(self, line):
        marker, _, holder = line.partition(" ")
        self.assertEqual(
            "USER_LOCK_HELD",
            marker,
            "Owned editor failed before its expected database latch",
        )
        self.assertTrue(
            holder.isdigit(), "Owned editor did not report its connection id"
        )
        return holder

    def editor_line(self, editor):
        ready, _, _ = select.select([editor.stdout], [], [], 15)
        self.assertTrue(
            ready, "Owned editor did not reach its deterministic database latch"
        )
        return editor.stdout.readline().strip()

    def editor_marker(self, editor, expected):
        self.assertEqual(
            expected,
            self.editor_line(editor),
            "Owned editor failed before its expected database latch",
        )

    def commit_locked_editor(self, editor, statement):
        editor.stdin.write(statement + "//\nCOMMIT//\nSELECT 'EDITOR_COMMITTED'//\n")
        editor.stdin.flush()
        self.editor_marker(editor, "EDITOR_COMMITTED")

    def stop_locked_editor(self, editor):
        if editor.stdin is not None:
            editor.stdin.close()
            editor.stdin = None
        try:
            editor.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            editor.terminate()
            editor.communicate(timeout=10)

    def receiver_timeout_detail(self, request):
        if request is None:
            receiver = "receiver request not supplied"
        elif not request.done():
            receiver = "receiver request still running"
        else:
            try:
                status, result = request.result()
                receiver = "receiver request already returned HTTP " + str(status)
                if isinstance(result, dict) and result.get("error"):
                    receiver += " (" + str(result["error"])[:200] + ")"
            except Exception as error:  # noqa: BLE001 - reported, not handled
                receiver = "receiver request raised " + type(error).__name__
        try:
            sessions = self.sql(
                "SELECT ID, COMMAND, COALESCE(STATE,''), TIME FROM information_schema.PROCESSLIST WHERE USER='keycloak' AND COMMAND<>'Sleep'"
            )
        except Exception as error:  # noqa: BLE001 - diagnostics must not mask the failure
            sessions = "unavailable (" + type(error).__name__ + ")"
        try:
            waits = self.sql(
                "SELECT w.requesting_trx_id, w.blocking_trx_id, l.lock_table, COALESCE(l.lock_index,'<NULL>'), l.lock_mode, COALESCE(l.lock_data,'<NULL>') FROM information_schema.INNODB_LOCK_WAITS w JOIN information_schema.INNODB_LOCKS l ON w.requested_lock_id=l.lock_id"
            )
        except Exception as error:  # noqa: BLE001 - diagnostics must not mask the failure
            waits = "unavailable (" + type(error).__name__ + ")"
        return (
            receiver
            + "; active keycloak sessions: "
            + (sessions or "none")
            + "; InnoDB lock waits: "
            + (" | ".join(waits.splitlines()) if waits else "none")
        )

    def wait_for_receiver_user_lock_and_read_view(self, user, request=None):
        deadline = time.monotonic() + self.RECEIVER_WAIT_SECONDS
        # The wait is on the target user's row when lock_data names it, or when
        # the lock is held by the owned editor, which locks only that row.
        # MariaDB 11.0 can report lock_data as NULL for the same wait.
        holder = getattr(self, "user_lock_holders", {}).get(user)
        held_by_editor = (
            " OR b.trx_mysql_thread_id=" + holder if holder else ""
        )
        while time.monotonic() < deadline:
            rows = self.sql(
                "SELECT t.trx_mysql_thread_id, p.USER, t.trx_isolation_level FROM information_schema.INNODB_LOCK_WAITS w JOIN information_schema.INNODB_LOCKS l ON w.requested_lock_id=l.lock_id JOIN information_schema.INNODB_TRX t ON w.requesting_trx_id=t.trx_id LEFT JOIN information_schema.INNODB_TRX b ON w.blocking_trx_id=b.trx_id JOIN information_schema.PROCESSLIST p ON p.ID=t.trx_mysql_thread_id WHERE l.lock_table LIKE '%USER_ENTITY%' AND (l.lock_data LIKE '%"
                + user
                + "%'"
                + held_by_editor
                + ")"
            )
            if rows:
                connection, account, isolation = rows.splitlines()[0].split("\t")
                self.assertEqual("keycloak", account)
                self.assertEqual("REPEATABLE READ", isolation)
                status = self.sql("SHOW ENGINE INNODB STATUS").replace("\\n", "\n")
                current = re.findall(
                    r"(?ms)^-+\nTRANSACTIONS\n-+\n(.*?)^-+\nFILE I/O\n-+\n",
                    status,
                )
                self.assertEqual(
                    1, len(current), "Current InnoDB transaction section is required"
                )
                blocks = [
                    block
                    for block in current[0].split("---TRANSACTION")[1:]
                    if re.search(r"thread id " + connection + r"\b", block)
                ]
                self.assertEqual(
                    1,
                    len(blocks),
                    "Actual receiver transaction must be visible in the InnoDB snapshot witness",
                )
                self.assertIn(
                    "read view",
                    blocks[0].lower(),
                    "Actual receiver must hold an established consistent-read view before acquiring the target lock",
                )
                return
            time.sleep(self.INNODB_VIEW_POLL_SECONDS)
        self.fail(
            "Receiver did not reach the actual target-user InnoDB wait: "
            + self.receiver_timeout_detail(request)
        )
