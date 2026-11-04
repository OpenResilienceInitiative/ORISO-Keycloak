"""The concurrency witness must use current, not historical, transactions."""

import unittest
import itertools
import mariadb_fixture
import base64
import contextlib
import io
import json
from concurrent.futures import Future
from unittest.mock import patch
from mariadb_fixture import MariaDbFixture


class Witness(MariaDbFixture, unittest.TestCase):
    pass


def transaction(thread, read_view=True):
    return (
        "---TRANSACTION 123, ACTIVE 1 sec\n"
        "MariaDB thread id "
        + thread
        + ", OS thread handle 1\n"
        + ("Trx read view will not see trx with id >= 9\n" if read_view else "")
    )


def monitor(active, historical=""):
    return (
        "------------------------\nLATEST DETECTED DEADLOCK\n"
        "------------------------\n"
        + historical
        + "------------\nTRANSACTIONS\n------------\n"
        + active
        + "--------\nFILE I/O\n--------\n"
    )


class InnoDbWitnessTest(unittest.TestCase):
    def witness(self, status):
        proof = Witness("runTest")
        Witness.lock_wait_receipts = []
        Witness.driver_latches = []
        Witness.metadata_last_read_finished = None
        Witness.metadata_cache_cadence = {
            "requiredIdleSeconds": 0.125,
            "minimumMeasuredGapSeconds": None,
            "measuredGaps": 0,
            "selectorQueries": 0,
            "diagnosticQueries": 0,
            "postReleaseQueries": 0,
        }
        proof.sql = lambda sql, timeout=None: (
            "7\tkeycloak\tREPEATABLE READ" if sql.startswith("SELECT") else status
        )
        return proof

    def test_metadata_observer_leaves_the_upstream_cache_refresh_idle(self):
        class Clock:
            now = 0.0

            @classmethod
            def monotonic(cls):
                return cls.now

            @classmethod
            def sleep(cls, seconds):
                cls.now += seconds

        proof = self.witness("")
        source = "before"
        cached = None
        last_read = None

        def upstream_cache(sql, timeout=None):
            nonlocal cached, last_read
            now = Clock.monotonic()
            # Pinned Maria trx0i_s.cc: every READ resets the 100ms idle clock.
            if last_read is None or now - last_read > 0.1:
                cached = source
            last_read = now
            return cached

        proof.sql = upstream_cache
        with patch.object(mariadb_fixture, "time", Clock):
            self.assertEqual("before", proof.metadata_cache_query("SELECT", "selector"))
            source = "after"
            self.assertEqual("before", upstream_cache("SELECT"))
            self.assertEqual("after", proof.metadata_cache_query("SELECT", "selector"))
        self.assertGreaterEqual(
            Witness.metadata_cache_cadence["minimumMeasuredGapSeconds"], 0.125
        )

    def test_old_deadlock_does_not_make_current_transaction_ambiguous(self):
        status = monitor(transaction("7"), transaction("7"))
        self.witness(status).wait_for_receiver_user_lock_and_read_view("synthetic-user")

    def test_old_deadlock_cannot_supply_the_current_read_view(self):
        status = monitor(transaction("8"), transaction("7"))
        with self.assertRaises(AssertionError):
            self.witness(status).wait_for_receiver_user_lock_and_read_view(
                "synthetic-user"
            )

    def test_two_current_matches_are_rejected(self):
        status = monitor(transaction("7") + transaction("7"))
        with self.assertRaises(AssertionError):
            self.witness(status).wait_for_receiver_user_lock_and_read_view(
                "synthetic-user"
            )

    def test_current_match_without_read_view_is_rejected(self):
        status = monitor(transaction("7", read_view=False))
        with self.assertRaises(AssertionError):
            self.witness(status).wait_for_receiver_user_lock_and_read_view(
                "synthetic-user"
            )


class FixtureDiagnosticTest(unittest.TestCase):
    def token(self, expiry):
        payload = (
            base64.urlsafe_b64encode(json.dumps({"exp": expiry}).encode())
            .decode()
            .rstrip("=")
        )
        return "synthetic." + payload + ".synthetic"

    def test_completed_http_status_is_recorded_but_missing_lock_still_fails(self):
        proof = InnoDbWitnessTest().witness("")
        proof.sql = lambda sql, timeout=None: ""
        future = Future()
        future.set_result((403, {"secret": "must-not-be-recorded"}))
        output = io.StringIO()
        with patch(
            "mariadb_fixture.time.monotonic",
            side_effect=itertools.chain((0,), itertools.repeat(16)),
        ), contextlib.redirect_stdout(output):
            with self.assertRaises(AssertionError):
                proof.wait_for_receiver_user_lock_and_read_view(
                    "synthetic-user", future, "commit"
                )
        self.assertEqual(1, len(Witness.lock_wait_receipts))
        evidence = json.dumps(Witness.lock_wait_receipts, sort_keys=True)
        self.assertIn('"httpStatus": 403', evidence)
        self.assertIn('"phase": "commit"', evidence)
        self.assertNotIn("must-not-be-recorded", evidence)
        self.assertNotIn("must-not-be-recorded", output.getvalue())

    def test_unexpired_installer_token_is_not_refreshed(self):
        proof = Witness("runTest")
        proof.base = "http://synthetic.invalid"
        proof.installer = self.token(200)
        with patch("mariadb_fixture.time.time", return_value=100), patch.object(
            Witness, "ready"
        ) as ready, patch("lifecycle_fixture.call", return_value=(200, {})):
            proof.admin("GET", "/users/profile")
        ready.assert_not_called()

    def test_only_expiring_installer_token_is_refreshed_before_admin_call(self):
        proof = Witness("runTest")
        proof.base = "http://synthetic.invalid"
        proof.installer = self.token(104)
        with patch("mariadb_fixture.time.time", return_value=100), patch.object(
            Witness, "ready"
        ) as ready, patch("lifecycle_fixture.call", return_value=(200, {})):
            proof.admin("GET", "/users/profile")
        ready.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
