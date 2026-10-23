"""Only the installed providers' exact key guards can explain startup refusal."""
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location("installed_image_guard_proof", ROOT / "scripts/ci/scenario-c-image-proof.py")
proof = importlib.util.module_from_spec(spec)
spec.loader.exec_module(proof)


class InstalledImageKeyGuardControls(unittest.TestCase):
    def test_all_four_independently_defined_guards_are_named_exactly(self):
        for guard, message in {
            "LIFECYCLE": "Lifecycle key must contain at least 32 bytes",
            "SMTP": "SMTP context key must contain at least 32 bytes",
            "PROTECTED": "Invalid protected context key",
            "SESSION": "Invalid session key length",
        }.items():
            for line in [message, "ERROR: " + message,
                         "Caused by: java.lang.IllegalStateException: " + message]:
                self.assertEqual([guard], proof.installed_key_guard_names(line))

    def test_missing_marker_or_unrelated_exit_never_explains_refusal(self):
        for text in ["", "ERROR: Server exited", "OutOfMemoryError", "ERROR: Invalid key",
                     "ERROR: Invalid session key length extra",
                     "quoted source mentions Invalid session key length"]:
            self.assertEqual([], proof.installed_key_guard_names(text))

    def test_duplicate_guard_logs_produce_one_nonsecret_enum(self):
        text = "ERROR: Invalid session key length\nERROR: Invalid session key length"
        self.assertEqual(["SESSION"], proof.installed_key_guard_names(text))


if __name__ == "__main__": unittest.main()
