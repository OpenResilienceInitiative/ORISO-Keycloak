"""The concurrency witness must use current, not historical, transactions."""

import unittest
from unittest.mock import patch
import mariadb_fixture
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


if __name__ == "__main__":
    unittest.main()
