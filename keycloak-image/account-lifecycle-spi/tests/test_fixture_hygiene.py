"""One timed-out subtest must not cascade into every later test of the class."""

from concurrent.futures import Future
import unittest
from unittest import mock

import lifecycle_fixture
from lifecycle_fixture import LifecycleFixture
from mariadb_fixture import MariaDbFixture


class Proof(LifecycleFixture, unittest.TestCase):
    base = "http://synthetic"


class Replica(MariaDbFixture, unittest.TestCase):
    RECEIVER_WAIT_SECONDS = 0.05


def reset_installer():
    for name in ("_installer_token", "_installer_issued_at"):
        if name in vars(Proof):
            delattr(Proof, name)


def token_response(token):
    return 200, {"access_token": token}


class InstallerTokenTest(unittest.TestCase):
    def setUp(self):
        Proof._installer_token = "old"
        Proof._installer_issued_at = 100.0
        self.addCleanup(reset_installer)
        self.proof = Proof("run")

    def test_fresh_token_is_reused(self):
        with mock.patch.object(lifecycle_fixture.time, "monotonic", return_value=120.0), \
                mock.patch.object(lifecycle_fixture, "call") as call:
            self.assertEqual("old", self.proof.installer)
        call.assert_not_called()

    def test_stale_token_is_renewed_before_the_60_second_expiry(self):
        with mock.patch.object(lifecycle_fixture.time, "monotonic", return_value=131.0), \
                mock.patch.object(lifecycle_fixture, "call", return_value=token_response("new")):
            self.assertEqual("new", self.proof.installer)
        self.assertEqual(131.0, Proof._installer_issued_at)

    def test_failed_renewal_keeps_previous_token_and_retries_later(self):
        with mock.patch.object(lifecycle_fixture.time, "monotonic", return_value=131.0), \
                mock.patch.object(lifecycle_fixture, "call", side_effect=OSError("down")):
            self.assertEqual("old", self.proof.installer)
        self.assertEqual(100.0, Proof._installer_issued_at)


class RealmCleanupTest(unittest.TestCase):
    def setUp(self):
        Proof._installer_token = "token"
        Proof._installer_issued_at = float("inf")
        self.addCleanup(reset_installer)
        self.proof = Proof("run")

    def test_deleted_or_absent_realm_is_accepted(self):
        for status in (204, 404):
            with mock.patch.object(lifecycle_fixture, "call", return_value=(status, None)):
                self.proof.delete_realm("synthetic-realm")

    def test_rejected_delete_is_reported_instead_of_leaking_the_realm(self):
        with mock.patch.object(lifecycle_fixture, "call", return_value=(401, None)):
            with self.assertRaisesRegex(AssertionError, "synthetic-realm returned 401"):
                self.proof.delete_realm("synthetic-realm")


class ReceiverTimeoutDetailTest(unittest.TestCase):
    def replica(self, sessions):
        proof = Replica("run")
        proof.sql = lambda sql: sessions if "PROCESSLIST WHERE USER" in sql else ""
        return proof

    def test_timeout_names_an_early_receiver_response(self):
        request = Future()
        request.set_result((403, {"error": "forbidden"}))
        with self.assertRaisesRegex(
            AssertionError, r"already returned HTTP 403 \(forbidden\).*sessions: none"
        ):
            self.replica("").wait_for_receiver_user_lock_and_read_view(
                "synthetic-user", request
            )

    def test_timeout_names_a_receiver_that_is_still_running(self):
        request = Future()
        with self.assertRaisesRegex(
            AssertionError, r"still running.*sessions: 9\tQuery\tSending data\t3"
        ):
            self.replica("9\tQuery\tSending data\t3").wait_for_receiver_user_lock_and_read_view(
                "synthetic-user", request
            )


if __name__ == "__main__":
    unittest.main()
