"""The concurrency witness must use current, not historical, transactions."""

import unittest
from mariadb_fixture import MariaDbFixture


class Witness(MariaDbFixture, unittest.TestCase):
    pass


def transaction(thread, read_view=True):
    return (
        "---TRANSACTION 123, ACTIVE 1 sec\n"
        "MariaDB thread id " + thread + ", OS thread handle 1\n"
        + ("Trx read view will not see trx with id >= 9\n" if read_view else "")
    )


def monitor(active, historical=""):
    return (
        "------------------------\nLATEST DETECTED DEADLOCK\n"
        "------------------------\n" + historical
        + "------------\nTRANSACTIONS\n------------\n"
        + active + "--------\nFILE I/O\n--------\n"
    )


class InnoDbWitnessTest(unittest.TestCase):
    def witness(self, status):
        proof = Witness("runTest")
        proof.sql = lambda sql: (
            "7\tkeycloak\tREPEATABLE READ"
            if sql.startswith("SELECT") else status
        )
        return proof

    def test_old_deadlock_does_not_make_current_transaction_ambiguous(self):
        status = monitor(transaction("7"), transaction("7"))
        self.witness(status).wait_for_receiver_user_lock_and_read_view("synthetic-user")

    def test_old_deadlock_cannot_supply_the_current_read_view(self):
        status = monitor(transaction("8"), transaction("7"))
        with self.assertRaises(AssertionError):
            self.witness(status).wait_for_receiver_user_lock_and_read_view("synthetic-user")

    def test_two_current_matches_are_rejected(self):
        status = monitor(transaction("7") + transaction("7"))
        with self.assertRaises(AssertionError):
            self.witness(status).wait_for_receiver_user_lock_and_read_view("synthetic-user")

    def test_current_match_without_read_view_is_rejected(self):
        status = monitor(transaction("7", read_view=False))
        with self.assertRaises(AssertionError):
            self.witness(status).wait_for_receiver_user_lock_and_read_view("synthetic-user")


if __name__ == "__main__":
    unittest.main()
