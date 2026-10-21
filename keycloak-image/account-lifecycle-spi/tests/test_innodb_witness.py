"""The concurrency witness must use current, not historical, transactions."""

import unittest
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
        proof.sql = lambda sql: (
            "7\tkeycloak\tREPEATABLE READ" if sql.startswith("SELECT") else status
        )
        return proof

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
        proof = Witness("runTest")
        proof.sql = lambda sql: ""
        future = Future()
        future.set_result((403, {"secret": "must-not-be-recorded"}))
        output = io.StringIO()
        with patch(
            "mariadb_fixture.time.monotonic", side_effect=[0, 16]
        ), contextlib.redirect_stdout(output):
            with self.assertRaises(AssertionError):
                proof.wait_for_receiver_user_lock_and_read_view(
                    "synthetic-user", future, "commit"
                )
        self.assertIn('"httpStatus": 403', output.getvalue())
        self.assertIn('"phase": "commit"', output.getvalue())
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
