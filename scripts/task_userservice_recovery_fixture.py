"""Optional joined UserService proof while the disposable command provider is live."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import xml.etree.ElementTree as XML


def verify_userservice_recovery(receiver, java_home, issuer, provisioning, provisioning_key, maintenance_key):
    receiver = Path(receiver).resolve()
    if not (receiver / "pom.xml").is_file():
        raise AssertionError("UserService receiver must be an existing Maven checkout")
    test_name = "IdentityCreationNativeRestartIT"
    if not list((receiver / "src/test").rglob(test_name + ".java")):
        raise AssertionError("Joined native restart test is missing from the receiver checkout")
    with tempfile.TemporaryDirectory(prefix="oriso-creation-native-fixture-") as directory:
        fixture = Path(directory) / "fixture.json"
        with open(fixture, "x", opener=lambda path, flags: os.open(path, flags, 0o600)) as handle:
            json.dump(
                {
                    "issuer": issuer,
                    "provisioning": provisioning,
                    "provisioningOriginKey": provisioning_key,
                    "maintenanceOriginKey": maintenance_key,
                },
                handle,
            )
        environment = os.environ.copy()
        environment["ORISO_CREATION_NATIVE_FIXTURE"] = str(fixture)
        if java_home:
            environment["JAVA_HOME"] = str(Path(java_home).resolve())
        log = Path("/tmp/oriso-367-userservice-native-creation-restart.log")
        started = time.time()
        with log.open("w") as output:
            os.chmod(log, 0o600)
            result = subprocess.run(
                ["./mvnw", "-B", "-q", "-Dtest=" + test_name, "test"],
                cwd=receiver,
                env=environment,
                stdout=output,
                stderr=subprocess.STDOUT,
                check=False,
            )
        if result.returncode:
            raise AssertionError("Joined UserService native restart gate failed; inspect its private local log")
        reports = list((receiver / "target/surefire-reports").glob("TEST-*" + test_name + ".xml"))
        if len(reports) != 1 or reports[0].stat().st_mtime < started:
            raise AssertionError("Joined native restart gate produced no fresh single-suite execution report")
        report = XML.parse(reports[0]).getroot()
        counts = {key: int(report.get(key, "0")) for key in ("tests", "failures", "errors", "skipped")}
        if counts["tests"] < 1 or any(counts[key] for key in ("failures", "errors", "skipped")):
            raise AssertionError("Joined native restart gate must execute cases without failure, error or skip")
        print(json.dumps({"userserviceNativeCreationRestart": counts}), flush=True)
