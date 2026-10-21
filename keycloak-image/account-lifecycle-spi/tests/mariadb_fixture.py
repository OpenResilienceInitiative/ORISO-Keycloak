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
    @classmethod
    def setUpClass(cls):
        cls.lock_wait_receipts = []
        cls.driver_latches = []
        cls.metadata_last_read_finished = None
        cls.metadata_cache_cadence = {
            "requiredIdleSeconds": 0.125,
            "minimumMeasuredGapSeconds": None,
            "measuredGaps": 0,
            "selectorQueries": 0,
            "diagnosticQueries": 0,
            "postReleaseQueries": 0,
        }
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
                "KC_BOOTSTRAP_ADMIN_USERNAME=synthetic-installer",
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
        # Master admin-cli tokens live60seconds; the expanded class now exceeds
        # that duration. Keep ordinary actor tokens and realm policies unchanged.
        type(self).ready()
        super().setUp()

    def admin(self, method, path="", body=None):
        # Only the fixture installer token may refresh. Tested actor JWTs/proofs
        # and their negative expiry cases pass through unchanged.
        try:
            encoded = self.installer.split(".")[1]
            expiry = json.loads(
                base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
            )["exp"]
            if not isinstance(expiry, int) or isinstance(expiry, bool):
                raise ValueError()
        except (ValueError, KeyError, IndexError, TypeError):
            raise AssertionError(
                "Fixture installer token must have its actual expiry"
            ) from None
        if expiry <= time.time() + 5:
            type(self).ready()
        return super().admin(method, path, body)

    def sql(self, statement, timeout=None):
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
            timeout=timeout,
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
        editor.stdin.write(
            "START TRANSACTION//\nSELECT ID INTO @held_user FROM USER_ENTITY WHERE ID='"
            + user
            + "' FOR UPDATE//\nSELECT 'USER_LOCK_HELD',CONNECTION_ID(),"
            + "IF(@held_user='"
            + user
            + "','MATCH','MISSING')//\n"
        )
        editor.stdin.flush()
        marker, connection, selected = self.editor_line(editor).split("\t")
        self.assertEqual("USER_LOCK_HELD", marker)
        self.assertTrue(connection.isdecimal())
        self.assertEqual(
            "MATCH", selected, "Owned driver must select the exact existing target row"
        )
        editor.oriso_connection = int(connection)
        editor.oriso_target_digest = hashlib.sha256(user.encode()).hexdigest()
        editor.oriso_selected_target = True
        if len(type(self).driver_latches) < 64:
            type(self).driver_latches.append(
                {
                    "connection": editor.oriso_connection,
                    "targetDigest": editor.oriso_target_digest,
                    "selectedExactTarget": True,
                }
            )
        return editor

    def editor_line(self, editor, timeout=15):
        ready, _, _ = select.select([editor.stdout], [], [], timeout)
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

    @staticmethod
    def receiver_state(receiver):
        result = {
            "receiverRunning": receiver.running() if receiver is not None else False,
            "receiverCompleted": receiver.done() if receiver is not None else False,
            "httpStatus": None,
            "receiverException": False,
            "exceptionClass": None,
        }
        if receiver is not None and receiver.done():
            if receiver.cancelled():
                result["receiverException"] = True
                result["exceptionClass"] = "CancelledError"
                return result
            error = receiver.exception()
            if error is not None:
                result["receiverException"] = True
                kind = type(error).__name__
                result["exceptionClass"] = (
                    kind
                    if kind
                    in {"TimeoutError", "URLError", "HTTPError", "AssertionError"}
                    else "OTHER"
                )
            else:
                status, _ = receiver.result()
                if (
                    isinstance(status, int)
                    and not isinstance(status, bool)
                    and 100 <= status <= 599
                ):
                    result["httpStatus"] = status
        return result

    def metadata_cache_query(self, statement, phase, *, deadline=None):
        # Both pinned Maria engines refresh this shared I_S cache only after
        # >100ms since its latest READ (trx0i_s.cc CACHE_MIN_IDLE_TIME_NS).
        # Rapid polling otherwise keeps its old snapshot alive indefinitely.
        cls = type(self)
        previous = cls.metadata_last_read_finished
        quiet = 0.125 if previous is None else 0.125 - (time.monotonic() - previous)
        if quiet > 0:
            time.sleep(quiet)
        now = time.monotonic()
        if previous is not None:
            gap = now - previous
            metrics = cls.metadata_cache_cadence
            minimum = metrics["minimumMeasuredGapSeconds"]
            metrics["minimumMeasuredGapSeconds"] = (
                gap if minimum is None else min(minimum, gap)
            )
            metrics["measuredGaps"] += 1
        cls.metadata_cache_cadence[phase + "Queries"] += 1
        try:
            remaining = None if deadline is None else deadline - time.monotonic()
            if remaining is not None and remaining <= 0:
                raise TimeoutError()
            return self.sql(statement, timeout=remaining)
        finally:
            cls.metadata_last_read_finished = time.monotonic()

    def missing_wait_observation(self, user, receiver, phase, editor):
        receipt = {
            **self.receiver_state(receiver),
            "phase": (
                phase
                if phase in {"commit", "compensate", "owned-read"}
                else "unspecified"
            ),
            "witnessObserved": False,
            "beforeDriverRelease": self.receiver_state(receiver),
            "driverAlive": editor is not None and editor.poll() is None,
            "driverConnection": getattr(editor, "oriso_connection", None),
            "driverSelectedExactTarget": getattr(
                editor, "oriso_selected_target", False
            ),
            "targetDigest": hashlib.sha256(user.encode()).hexdigest(),
            "waits": [],
            "processes": {},
        }
        deadline = time.monotonic() + 5

        def query(statement):
            return self.metadata_cache_query(statement, "diagnostic", deadline=deadline)

        try:
            self.assertEqual(user, str(uuid.UUID(user)))
            connection = receipt["driverConnection"]
            self.assertIsInstance(connection, int)
            raw = query(
                "SELECT r.trx_mysql_thread_id, b.trx_mysql_thread_id, r.trx_state, r.trx_isolation_level,"
                " l.lock_table, l.lock_index, l.lock_type, l.lock_mode, IF(l.lock_data IS NULL,1,0),"
                " IF(l.lock_data LIKE '%"
                + user
                + "%',1,0) FROM information_schema.INNODB_LOCK_WAITS w"
                " JOIN information_schema.INNODB_LOCKS l ON w.requested_lock_id=l.lock_id"
                " JOIN information_schema.INNODB_TRX r ON w.requesting_trx_id=r.trx_id"
                " JOIN information_schema.INNODB_TRX b ON w.blocking_trx_id=b.trx_id"
                " JOIN information_schema.PROCESSLIST p ON p.ID=r.trx_mysql_thread_id"
                " WHERE p.USER='keycloak' ORDER BY r.trx_mysql_thread_id LIMIT 16"
            )
            for row in raw.splitlines()[:16]:
                (
                    requester,
                    blocker,
                    state,
                    isolation,
                    table,
                    index,
                    kind,
                    mode,
                    null_key,
                    target_key,
                ) = row.split("\t")
                known_table = next(
                    (
                        name
                        for name in (
                            "USER_ENTITY",
                            "REALM",
                            "KEYCLOAK_GROUP",
                            "KEYCLOAK_ROLE",
                            "USER_ATTRIBUTE",
                            "USER_ROLE_MAPPING",
                            "USER_GROUP_MEMBERSHIP",
                            "CREDENTIAL",
                            "ORISO_ACCOUNT_LIFECYCLE_ATTEMPT",
                        )
                        if name in table
                    ),
                    "OTHER",
                )
                receipt["waits"].append(
                    {
                        "requesterConnection": int(requester),
                        "blockerConnection": int(blocker),
                        "blockedByOwnedDriver": int(blocker) == connection,
                        "table": known_table,
                        "indexClass": (
                            "PRIMARY" if index == "PRIMARY" else "SECONDARY_OR_OTHER"
                        ),
                        "state": (
                            state
                            if state
                            in {"RUNNING", "LOCK WAIT", "ROLLING BACK", "COMMITTING"}
                            else "OTHER"
                        ),
                        "isolation": (
                            isolation
                            if isolation
                            in {
                                "REPEATABLE READ",
                                "READ COMMITTED",
                                "SERIALIZABLE",
                                "READ UNCOMMITTED",
                            }
                            else "OTHER"
                        ),
                        "lockType": kind if kind in {"RECORD", "TABLE"} else "OTHER",
                        "exclusive": mode.startswith("X"),
                        "lockKeyNull": null_key == "1",
                        "lockKeyMatchesTarget": target_key == "1",
                    }
                )
            receipt["waitSampleAtLimit"] = len(receipt["waits"]) == 16
            owner = query(
                "SELECT COUNT(*) FROM information_schema.INNODB_TRX WHERE trx_mysql_thread_id="
                + str(connection)
            )
            receipt["driverHasCurrentTransaction"] = owner == "1"
            raw = query(
                "SELECT p.COMMAND, IF(p.STATE LIKE '%lock%',1,0), IF(t.trx_id IS NULL,0,1)"
                " FROM information_schema.PROCESSLIST p LEFT JOIN information_schema.INNODB_TRX t ON p.ID=t.trx_mysql_thread_id"
                " WHERE p.USER='keycloak' ORDER BY p.ID LIMIT 32"
            )
            counts = {
                "sampled": 0,
                "query": 0,
                "sleep": 0,
                "lockState": 0,
                "transaction": 0,
            }
            for row in raw.splitlines()[:32]:
                command, locked, transaction = row.split("\t")
                counts["sampled"] += 1
                counts["query"] += command == "Query"
                counts["sleep"] += command == "Sleep"
                counts["lockState"] += locked == "1"
                counts["transaction"] += transaction == "1"
            receipt["processes"] = counts
            receipt["processSampleAtLimit"] = counts["sampled"] == 32
        except Exception as error:
            receipt["diagnosticErrorClass"] = (
                type(error).__name__
                if type(error).__name__
                in {"TimeoutExpired", "TimeoutError", "AssertionError", "ValueError"}
                else "OTHER"
            )
        type(self).lock_wait_receipts.append(receipt)
        self.current_wait_receipt = receipt
        return receipt

    def release_failed_witness(self, editor, receiver):
        # Release only our own transaction before executor teardown can wait on it.
        receipt = getattr(self, "current_wait_receipt", None)
        try:
            editor.stdin.write("ROLLBACK//\nSELECT 'EDITOR_ROLLED_BACK'//\n")
            editor.stdin.flush()
            self.assertEqual("EDITOR_ROLLED_BACK", self.editor_line(editor, timeout=5))
            if receipt is not None:
                receipt["driverRollbackAcknowledged"] = True
        except Exception as error:
            if receipt is not None:
                receipt["driverReleaseErrorClass"] = (
                    type(error).__name__
                    if type(error).__name__
                    in {"AssertionError", "BrokenPipeError", "OSError"}
                    else "OTHER"
                )
        finally:
            self.stop_locked_editor(editor)
        if receipt is not None:
            try:
                owner = self.metadata_cache_query(
                    "SELECT COUNT(*) FROM information_schema.INNODB_TRX WHERE trx_mysql_thread_id="
                    + str(editor.oriso_connection),
                    "postRelease",
                    deadline=time.monotonic() + 2,
                )
                receipt["driverTransactionReleased"] = owner == "0"
            except Exception as error:
                receipt["driverReleaseObservationErrorClass"] = (
                    type(error).__name__
                    if type(error).__name__ in {"AssertionError", "TimeoutExpired"}
                    else "OTHER"
                )
        try:
            receiver.result(timeout=5)
        except Exception:
            pass
        if receipt is not None:
            receipt["afterDriverRelease"] = self.receiver_state(receiver)
            receipt["driverStopped"] = editor.poll() is not None

    def wait_for_receiver_user_lock_and_read_view(
        self, user, receiver=None, phase=None, editor=None
    ):
        self.current_wait_receipt = None
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            rows = self.metadata_cache_query(
                "SELECT t.trx_mysql_thread_id, p.USER, t.trx_isolation_level FROM information_schema.INNODB_LOCK_WAITS w JOIN information_schema.INNODB_LOCKS l ON w.requested_lock_id=l.lock_id JOIN information_schema.INNODB_TRX t ON w.requesting_trx_id=t.trx_id JOIN information_schema.PROCESSLIST p ON p.ID=t.trx_mysql_thread_id WHERE l.lock_table LIKE '%USER_ENTITY%' AND l.lock_data LIKE '%"
                + user
                + "%'",
                "selector",
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
            time.sleep(0.125)
        self.missing_wait_observation(user, receiver, phase, editor)
        self.fail("Receiver did not reach the actual target-user InnoDB wait")
