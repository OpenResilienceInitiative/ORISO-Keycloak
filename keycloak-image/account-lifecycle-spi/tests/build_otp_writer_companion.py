#!/usr/bin/env python3
"""Compile a proof-only JAR in the fresh hosted job, never in the product tree."""

import argparse
import hashlib
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import zipfile

from protected_resources import HOSTED_PROFILE, require_start


def build(destination):
    if (
        platform.system() != "Linux"
        or os.environ.get("PROTECTED_PROOF_RESOURCE_PROFILE") != HOSTED_PROFILE
    ):
        raise RuntimeError(
            "Companion compilation requires the approved hosted Linux policy"
        )
    require_start()
    module = Path(__file__).resolve().parent.parent
    fixture = module / "tests/native-otp-writer-fixture"
    output = Path(destination).resolve()
    runner_temp = Path(os.environ["RUNNER_TEMP"]).resolve()
    if (
        output.parent != runner_temp
        or output.name != "oriso-proof-otp-writer-companion.jar"
        or output.exists()
    ):
        raise RuntimeError(
            "Companion output must be a new exact owned runner temporary file"
        )
    main = Path(os.environ["LIFECYCLE_C_TEST_JAR"]).resolve()
    main_before = hashlib.sha256(main.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(
        prefix="oriso-proof-compile-", dir=runner_temp
    ) as folder:
        work = Path(folder)
        classpath = work / "classpath.txt"
        env = {
            **os.environ,
            "MAVEN_OPTS": "-Xmx256m -XX:MaxMetaspaceSize=192m -XX:ActiveProcessorCount=2",
        }
        subprocess.run(
            [
                "mvn",
                "-B",
                "-q",
                "org.apache.maven.plugins:maven-dependency-plugin:3.8.1:build-classpath",
                "-DincludeScope=compile",
                "-Dmdep.outputFile=" + str(classpath),
            ],
            cwd=module,
            env=env,
            check=True,
            timeout=120,
        )
        classes = work / "classes"
        classes.mkdir()
        sources = sorted((fixture / "src").rglob("*.java"))
        if len(sources) != 1:
            raise RuntimeError("Exact single companion source required")
        subprocess.run(
            [
                "javac",
                "-J-Xmx256m",
                "-J-XX:MaxMetaspaceSize=192m",
                "-J-XX:ActiveProcessorCount=2",
                "--release",
                "17",
                "-cp",
                str(main) + os.pathsep + classpath.read_text().strip(),
                "-d",
                str(classes),
                *map(str, sources),
            ],
            check=True,
            timeout=60,
        )
        entries = sorted(classes.rglob("*.class"))
        if not entries or any(
            not str(p.relative_to(classes)).startswith(
                "org/oriso/keycloak/lifecycle/proof/"
            )
            for p in entries
        ):
            raise RuntimeError("Unexpected companion class inventory")
        service = "META-INF/services/org.keycloak.email.EmailSenderProviderFactory"
        with zipfile.ZipFile(output, "x", compression=zipfile.ZIP_DEFLATED) as archive:
            for file in entries:
                archive.write(file, str(file.relative_to(classes)))
            archive.write(fixture / service, service)
    if main_before != hashlib.sha256(main.read_bytes()).hexdigest():
        raise RuntimeError("Main provider changed during companion compilation")
    print("Proof-only native sender observer compiled outside product artifacts")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--jar", required=True)
    build(parser.parse_args().jar)
