#!/usr/bin/env python3
"""Finite S1 tracer using an immutable reviewed resource adapter; no success inferred from setup."""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen
import uuid
import xml.etree.ElementTree as ET
import zipfile
sys.dont_write_bytecode = True

HELPER_SHA = "37d29adc5e8e31aac9467e1ca1c1587b2d84db6239ea79f016cd0442f7916fec"
LEASE_MIB, CONTAINER_MIB = 3152, 1024
USER_SUITE = "de.caritas.cob.userservice.api.config.auth.SessionExchangeTokenBoundaryTest"
NATIVE_SUITE = "session_exchange_native.SessionExchangeNative"
USER_FILES = (
    "src/main/java/de/caritas/cob/userservice/api/config/auth/TaskActorTokenBroker.java",
    "src/test/java/de/caritas/cob/userservice/api/config/auth/SessionExchangeTokenBoundaryTest.java",
)


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def git(root, *args):
    return subprocess.check_output(["git", *args], cwd=root, text=True).strip()


def snapshot(root):
    names = subprocess.check_output(["git", "ls-files", "-z"], cwd=root).decode().split("\0")
    return {name: hashlib.sha256(b"symlink\0" + os.readlink(root / name).encode()
            if (root / name).is_symlink() else (root / name).read_bytes()).hexdigest()
            for name in sorted(filter(None, names))}


def exact(root, ref):
    if not re.fullmatch("[a-f0-9]{40}", ref) or git(root, "rev-parse", "HEAD") != ref:
        raise RuntimeError("Immutable exact source required")
    if git(root, "status", "--porcelain"):
        raise RuntimeError("Clean source required")


def groups_ok(groups, number):
    return (len(groups) == number and len({g.get("processGroup") for g in groups}) == number
            and all(type(g.get("processGroup")) is int and g["processGroup"] > 0
                    and g.get("confirmedAbsent") is True for g in groups))


OBSERVATION_FLAGS = {"fixtureClaimOnly", "fiveActorsExact", "adminNoDirectGrant", "adminCannotQueryUsers",
    "ordinaryPasswordLogin", "sourceOtpExecutionsPreserved", "nativeRouterSelected", "commandMacValid", "nativeVersionPinned"}


def checked_observation(value):
    if not isinstance(value, dict) or set(value) != OBSERVATION_FLAGS | {"magicStatus"}:
        raise RuntimeError("Fixed native observation catalogue required")
    if any(type(value[k]) is not bool for k in OBSERVATION_FLAGS):
        raise RuntimeError("Only exact native booleans may be exported")
    if type(value["magicStatus"]) is not int or not 0 <= value["magicStatus"] <= 599:
        raise RuntimeError("Finite native HTTP status required")
    return value


def native_classification(receipt):
    observed = checked_observation(receipt["observed"])
    preconditions = OBSERVATION_FLAGS - {"nativeRouterSelected"}
    counts = receipt.get("counts")
    if (not isinstance(counts, dict) or set(counts) != {"tests", "failures", "errors", "skipped"}
            or any(type(v) is not int or v < 0 for v in counts.values())
            or not all(observed[k] is True for k in preconditions)
            or receipt.get("cases") not in ([{"name":"test_checked_claim_enters_native_session_path", "outcome":"failure"}],
                                             [{"name":"test_checked_claim_enters_native_session_path", "outcome":"pass"}])):
        raise RuntimeError("Complete actual native preconditions/inventory required")
    if counts == {"tests":1,"failures":1,"errors":0,"skipped":0} and observed["nativeRouterSelected"] is True and observed["magicStatus"] == 401 and receipt["cases"][0]["outcome"] == "failure":
        return "ACTUAL_NATIVE_SESSION_ASSERTION_RED"
    if counts == {"tests":1,"failures":0,"errors":0,"skipped":0} and observed["magicStatus"] == 200 and receipt["cases"][0]["outcome"] == "pass":
        return "NATIVE_TRACER_GREEN_INCOMPLETE"
    raise RuntimeError("Native tracer outcome is not qualified")


def runtime_known(cleanup):
    rows = [r.get("runtime") for r in cleanup if r.get("kind") == "container"]
    return (len(rows) == 1 and isinstance(rows[0], dict) and rows[0].get("oomKilled") is False
            and type(rows[0].get("restartCount")) is int and rows[0]["restartCount"] == 0)


def named_groups_ok(groups, executed, planned):
    return isinstance(planned,list) and executed == planned and groups_ok(groups,len(planned))


def compile_diagnostics(log):
    value = log.read_text(errors="replace")
    return {"spotlessConfirmed": "The following files had format violations:" in value
            and "Run 'mvn spotless:apply'" in value,
            "ownedFilesMentioned": [Path(p).name for p in USER_FILES if Path(p).name in value],
            "compilerFailure": "maven-compiler-plugin" in value and "[ERROR]" in value}


def native_failure_frames(value):
    frames, types = [], []
    for line in value.splitlines():
        match = re.search(r"\bat ((?:org\.oriso|de\.onlineberatung|org\.keycloak)\.[A-Za-z0-9_.$<>]+)\(([A-Za-z0-9_$.-]+\.java):(\d+)\)", line)
        if match:
            row = {"method":match[1],"file":match[2],"line":int(match[3])}
            if row not in frames: frames.append(row)
        match = re.search(r"\b((?:java\.lang|org\.keycloak|org\.hibernate|io\.quarkus|jakarta)\.[A-Za-z0-9_.$]+(?:Exception|Error))(?=:|$)",line)
        if match and match[1] not in types: types.append(match[1])
    return {"exceptionTypes":types[:8],"sourceFrames":frames[-12:]}


def format_allowed(changed, untracked):
    return bool(changed) and set(changed).issubset(USER_FILES) and not untracked


def empty_owned_scratch(scratch, owner, runtemp):
    if (scratch.is_symlink() or scratch.parent != runtemp.resolve()
            or not scratch.name.startswith("s1-owned-user-format-") or not scratch.is_dir()):
        return False
    stat = scratch.stat()
    return (stat.st_dev,stat.st_ino,stat.st_uid) == owner and not list(scratch.iterdir())


def planned_groups(role, formatted=False):
    if type(formatted) is not bool or role not in {"user","native"} or (role == "native" and formatted):
        raise RuntimeError("Known role/formatter-attempt state required")
    if role == "native":
        return ["toolchain","lifecycle-compile","otp-compile","native-test"]
    return ["toolchain","user-compile","user-formatter" if formatted else "user-tests"]


def verify_format_delta(user, scratch, ref, deadline):
    def checked_git(root, *args):
        remaining = deadline-time.monotonic()
        if remaining <= 0:
            raise RuntimeError("Original compile deadline exhausted")
        return subprocess.check_output(["git",*args],cwd=root,timeout=min(30,remaining))
    if (checked_git(user,"rev-parse","HEAD").decode().strip() != ref
            or checked_git(user,"status","--porcelain")
            or checked_git(scratch,"rev-parse","HEAD").decode().strip() != ref
            or (scratch/checked_git(scratch,"rev-parse","--git-common-dir").decode().strip()).resolve()
            != (user/checked_git(user,"rev-parse","--git-common-dir").decode().strip()).resolve()):
        raise RuntimeError("Exact owned formatter sources required")
    changed = checked_git(scratch,"diff","--name-only").decode().splitlines()
    if not format_allowed(changed,checked_git(scratch,"ls-files","--others","--exclude-standard")):
        raise RuntimeError("Any unowned formatter delta refuses")
    patch = checked_git(scratch,"diff","--",*USER_FILES)
    return patch,{"changedPaths":changed,"patchSHA256":hashlib.sha256(patch).hexdigest()}


def mechanical_proposal(user, ref, support, env, private, out, deadline, report):
    # Same live MemoryLease/baseline as failed compilation; never reset for the formatter.
    if git(user,"rev-parse","HEAD") != ref or git(user,"status","--porcelain"):
        raise RuntimeError("Exact clean original formatter source required")
    before = snapshot(user)
    scratch = Path(tempfile.mkdtemp(prefix="s1-owned-user-format-",dir=os.environ["RUNNER_TEMP"]))
    stat = scratch.stat()
    owner = (stat.st_dev,stat.st_ino,stat.st_uid)
    receipt = {"state":"NO_PROPOSAL","ref":ref,"allowedPaths":list(USER_FILES),
               "sourceBefore":before,"scratchConfirmedAbsent":False}
    try:
        git(user,"worktree","add","--detach",str(scratch),ref)
        if git(scratch,"rev-parse","HEAD") != ref:
            raise RuntimeError("Immutable scratch source required")
        scope = "|".join(re.escape(str(scratch/p)) for p in USER_FILES)
        report["executedGroupNames"].append("user-formatter")
        result = support.bounded([str(scratch/"mvnw"),"-B","-ntp","-q",
            "-DspotlessFiles="+scope,"spotless:apply"],scratch,env,private/"formatter.log",420,deadline)
        if result:
            raise RuntimeError("Scoped owned formatter failed")
        patch,delta = verify_format_delta(user,scratch,ref,deadline)
        receipt.update(delta)
        receipt["state"] = "MECHANICAL_PROPOSAL_ONLY"
    finally:
        if scratch.exists():
            if empty_owned_scratch(scratch,owner,Path(os.environ["RUNNER_TEMP"])):
                scratch.rmdir()
            else:
                stat = scratch.stat()
                common = (user/ git(user,"rev-parse","--git-common-dir")).resolve()
                scratch_common = (scratch/git(scratch,"rev-parse","--git-common-dir")).resolve()
                if (scratch.is_symlink() or (stat.st_dev,stat.st_ino,stat.st_uid) != owner
                        or scratch.parent != Path(os.environ["RUNNER_TEMP"]).resolve()
                        or not scratch.name.startswith("s1-owned-user-format-")
                        or git(scratch,"rev-parse","HEAD") != ref or scratch_common != common):
                    raise RuntimeError("Exact scratch ownership unavailable; removal refused")
                git(user,"worktree","remove","--force",str(scratch))
        receipt["sourceAfter"] = snapshot(user)
        receipt["originalSourcesStable"] = receipt["sourceAfter"] == before
        receipt["scratchConfirmedAbsent"] = not scratch.exists()
        receipt["totalDeadlineRetained"] = time.monotonic() <= deadline
        if not all(receipt[k] for k in ("originalSourcesStable","scratchConfirmedAbsent","totalDeadlineRetained")):
            receipt["state"] = "NO_ACCEPTANCE"
        (out/"mechanical-receipt.json").write_text(json.dumps(receipt,indent=2)+"\n")
    if receipt["state"] != "MECHANICAL_PROPOSAL_ONLY":
        raise RuntimeError("No qualified mechanical proposal")
    (out/"mechanical.patch").write_bytes(patch)
    return receipt


def safe_xml(reports, out):
    inventory = {}
    for path in sorted(reports.glob("TEST-*.xml")):
        tree = ET.parse(path).getroot()
        name = tree.get("name")
        if name in inventory:
            raise RuntimeError("Duplicate XML suite")
        counts = {k: int(tree.get(k, "0")) for k in ("tests", "failures", "errors", "skipped")}
        cases = tree.findall("testcase")
        if len(cases) != counts["tests"] or any(
                sum(c.find(tag) is not None for c in cases) != counts[key]
                for tag, key in (("failure","failures"),("error","errors"),("skipped","skipped"))):
            raise RuntimeError("Incomplete or inconsistent testcase inventory")
        clean = ET.Element("testsuite", name=name, **{k: str(v) for k, v in counts.items()})
        for case in cases:
            row = ET.SubElement(clean, "testcase", name=case.get("name"), classname=name)
            for tag in ("failure", "error", "skipped"):
                if case.find(tag) is not None:
                    ET.SubElement(row, tag, message="S1 finite gate did not pass")
        ET.ElementTree(clean).write(out / path.name, encoding="utf-8", xml_declaration=True)
        inventory[name] = counts
    return inventory


def child():
    root = Path(__file__).resolve().parents[2]
    folder = root / "keycloak-image/account-lifecycle-spi/tests"
    sys.path.insert(0, str(folder))
    module = load("session_exchange_native", folder / "session_exchange_native.py")
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(module.SessionExchangeNative)
    if suite.countTestCases() != 1:
        raise RuntimeError("Exact finite native tracer required")
    class Result(unittest.TestResult):
        def __init__(self):
            super().__init__()
            self.rows = []
        def startTest(self, test):
            super().startTest(test)
            self.rows.append({"name": test._testMethodName, "outcome": "pass"})
        def addFailure(self, test, err):
            super().addFailure(test, err)
            self.rows[-1]["outcome"] = "failure"
        def addError(self, test, err):
            super().addError(test, err)
            if self.rows:
                self.rows[-1]["outcome"] = "error"
        def addSkip(self, test, reason):
            super().addSkip(test, reason)
            self.rows[-1]["outcome"] = "skipped"
    result = Result()
    suite.run(result)
    out = Path(os.environ["S1_CHILD_EVIDENCE"])
    counts = {"tests": result.testsRun, "failures": len(result.failures),
              "errors": len(result.errors), "skipped": len(result.skipped)}
    tree = ET.Element("testsuite", name=NATIVE_SUITE, **{k: str(v) for k, v in counts.items()})
    for case in result.rows:
        row = ET.SubElement(tree, "testcase", name=case["name"], classname=NATIVE_SUITE)
        if case["outcome"] != "pass":
            ET.SubElement(row, case["outcome"], message="S1 finite native tracer did not pass")
    ET.ElementTree(tree).write(out / ("TEST-" + NATIVE_SUITE + ".xml"), encoding="utf-8", xml_declaration=True)
    (out / "native-observation.json").write_text(json.dumps({
        "counts": counts, "cases": result.rows, "observed": checked_observation(module.OBSERVATIONS)}, sort_keys=True) + "\n")
    return 0 if result.wasSuccessful() else 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("role", choices=("user", "native"))
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--source-ref", required=True)
    parser.add_argument("--support", type=Path, required=True)
    parser.add_argument("--support-ref", required=True)
    parser.add_argument("--user", type=Path, required=True)
    parser.add_argument("--user-ref", required=True)
    parser.add_argument("--evidence", type=Path, required=True)
    args = parser.parse_args()
    root, helper, user, out = args.source.resolve(), args.support.resolve(), args.user.resolve(), args.evidence.resolve()
    out.mkdir(parents=True, exist_ok=False)
    roots = {"source": root, "support": helper, "user": user}
    refs = {"source": args.source_ref, "support": args.support_ref, "user": args.user_ref}
    for name, folder in roots.items():
        exact(folder, refs[name])
    if hashlib.sha256((helper / "scripts/native_context_resources.py").read_bytes()).hexdigest() != HELPER_SHA:
        raise RuntimeError("Reviewed immutable resource adapter required")
    support = load("s1_reviewed_support", helper / "scripts/test-bootstrap-context-roundtrip.py")
    support.configure_memory(LEASE_MIB, out)
    before = {name: snapshot(folder) for name, folder in roots.items()}
    overall = time.monotonic() + 1200
    report = {"role": args.role, "refs": refs, "sourceBefore": before, "classification": "SETUP_FAILURE",
              "nativeClaimAuthority": "fixture signed claim only; final User/Redis/Broker path not proved" if args.role == "native" else "HTTP/JWKS broker only; no native session or claim authority",
              "resourceBudgetMiB": LEASE_MIB, "helperSHA256": HELPER_SHA, "accepted": False}
    owned, private, private_owner = None, None, None
    status = 1
    try:
        support.memory_lease.check(starting=True)
        private = Path(tempfile.mkdtemp(prefix="s1-private-"))
        private.chmod(0o700)
        stat = private.stat()
        private_owner = (stat.st_dev, stat.st_ino, stat.st_uid)
        env = {**os.environ, "MAVEN_OPTS": "-Xmx512m -XX:MaxMetaspaceSize=192m -XX:ActiveProcessorCount=2",
               "JAVA_TOOL_OPTIONS": "-Xmx384m -XX:MaxMetaspaceSize=192m -XX:ActiveProcessorCount=2",
               "PYTHONDONTWRITEBYTECODE": "1"}
        wrapper = str(user / "mvnw")
        common = [wrapper, "-B", "-ntp", "-q", "-Dmaven.wagon.http.retryHandler.count=3"]
        compile_end = min(time.monotonic() + 420, overall)
        report["plannedGroups"] = planned_groups(args.role)
        report["executedGroupNames"] = ["toolchain"]
        report["toolchainExit"] = support.bounded([wrapper, "--version"], user, env,
            private / "toolchain.log", 60, compile_end)
        version = (private / "toolchain.log").read_text(errors="replace")
        report["toolchainPinned"] = "Apache Maven 3.9.15" in version and "Java version: 21.0.12" in version
        if report["toolchainExit"] or not report["toolchainPinned"]:
            raise RuntimeError("Pinned actual Maven/Java runtime required")
        if args.role == "user":
            if (user / "target").exists():
                raise RuntimeError("Fresh user compiled output required")
            scoped = "|".join(re.escape(str(user / p)) for p in USER_FILES)
            command = [*common, "-DspotlessFiles=" + scoped, "test-compile"]
            report["executedGroupNames"].append("user-compile")
            report["compileExit"] = support.bounded(command, user, env, private / "user-compile.log", 420, compile_end)
            if report["compileExit"]:
                report["compileDiagnostics"] = compile_diagnostics(private/"user-compile.log")
                if report["compileDiagnostics"]["spotlessConfirmed"]:
                    report["formatterAttempted"] = True
                    report["plannedGroups"] = planned_groups(args.role,True)
                    report["testsNotStartedBecauseCompileFailed"] = True
                    report["formatProposal"] = mechanical_proposal(user,args.user_ref,support,env,private,out,compile_end,report)
                    report["classification"] = "MECHANICAL_PROPOSAL_ONLY_NO_FEATURE_RED"
                return 1
            compiled = user / "target/test-classes" / Path(USER_SUITE.replace(".", "/") + ".class")
            report["compiledTestSHA256"] = hashlib.sha256(compiled.read_bytes()).hexdigest()
            reports = user / "target/surefire-reports"
            if reports.exists():
                raise RuntimeError("Fresh user XML directory required")
            report["executedGroupNames"].append("user-tests")
            report["testExit"] = support.bounded([*common, "-Dtest=" + USER_SUITE,
                "-DfailIfNoTests=true", "-DforkCount=1", "-DreuseForks=false",
                "-DargLine=-Xmx384m -XX:MaxMetaspaceSize=192m -XX:ActiveProcessorCount=2", "test"],
                user, env, private / "user-tests.log", 240, overall)
            report["suites"] = safe_xml(reports, out)
            if set(report["suites"]) != {USER_SUITE}:
                raise RuntimeError("Exact selected user suite required")
            counts = report["suites"][USER_SUITE]
            if counts["tests"] != 3 or counts["errors"] or counts["skipped"]:
                raise RuntimeError("Complete three-case user inventory required")
            report["classification"] = "USER_ASSERTION_RED" if counts["failures"] else "USER_FOCUSED_GREEN"
            status = int(bool(counts["failures"]))
        else:
            module = root / "keycloak-image/account-lifecycle-spi"
            otp = root / "keycloak-image/otp-config-spi"
            # The ORIGINAL full unit inventories execute before any disposable actor/container.
            for name, folder, goal in (("lifecycle", module, "install"), ("otp", otp, "package")):
                if (folder / "target").exists():
                    raise RuntimeError("Fresh native compiled output required")
                report["executedGroupNames"].append(name+"-compile")
                report[name + "CompileExit"] = support.bounded([*common, "-f", str(folder / "pom.xml"),
                    "-DargLine=-Xmx256m -XX:MaxMetaspaceSize=192m -XX:ActiveProcessorCount=2", goal],
                    root, env, private / (name + "-compile.log"), 420, compile_end)
                if report[name + "CompileExit"]:
                    report[name+"CompileDiagnostics"] = compile_diagnostics(private/(name+"-compile.log"))
                    return 1
                phase = out / (name + "-units")
                phase.mkdir()
                report[name + "Units"] = safe_xml(folder / "target/surefire-reports", phase)
                if not report[name + "Units"] or any(c[k] for c in report[name + "Units"].values()
                        for k in ("failures", "errors", "skipped")):
                    raise RuntimeError("Original complete native units required")
                sys.path.insert(0, str(module / "tests"))
                if name == "lifecycle":
                    verifier = load("s1_lifecycle_units", module / "tests/run_maintenance.py")
                    report["lifecycleUnitCatalog"] = verifier.sanitize_units(folder / "target/surefire-reports", phase / "catalog.xml")
                    if report["lifecycleUnitCatalog"]["accepted"] is not True:
                        raise RuntimeError("Original exact lifecycle unit catalog required")
                else:
                    verifier = load("s1_otp_units", module / "tests/run_scoped_otp.py")
                    if verifier.units(phase / "catalog.json"):
                        raise RuntimeError("Original exact OTP method catalog required")
            jars = {"lifecycle": module / "target/account-lifecycle-spi-1.0-SNAPSHOT.jar",
                    "otp": otp / "target/keycloak-otp-config-spi-1.0-SNAPSHOT-keycloak.jar"}
            report["jarSHA256"] = {name: hashlib.sha256(p.read_bytes()).hexdigest() for name, p in jars.items()}
            compiled = module / "target/classes/org/oriso/keycloak/lifecycle/MagicLinkAuthenticator.class"
            report["compiledAuthenticatorSHA256"] = hashlib.sha256(compiled.read_bytes()).hexdigest()
            with zipfile.ZipFile(jars["lifecycle"]) as jar:
                if jar.read("org/oriso/keycloak/lifecycle/MagicLinkAuthenticator.class") != compiled.read_bytes():
                    raise RuntimeError("Actual packaged authenticator must match compiled class")
            native = load("s1_native_fixture", module / "tests/lifecycle_fixture.py")
            run = uuid.uuid4().hex
            owned = support.resources.OwnedDocker("oriso-s1-run", run)
            network, container = "oriso-s1-net-" + run[:12], "oriso-s1-kc-" + run[:12]
            owned.plan("network", network)
            owned.plan("container", container)
            report["runId"] = run
            report["planned"] = [{"kind": k, "name": v} for k, v in owned.planned]
            for kind, name in owned.planned:
                if owned.inspect(kind, name) is not None:
                    raise RuntimeError("Planned exact resource already exists")
            support.free_guard()
            support.resources.docker("pull", native.IMAGE)
            support.resources.docker("network", "create", "--label", "oriso-s1-run=" + run, network)
            command = ["run", "-d", "--name", container, "--label", "oriso-s1-run=" + run,
                       "--network", network, "--memory", "1024m", "--memory-swap", "1024m",
                       "--cpus", "2", "-p", "127.0.0.1::8080"]
            values = {"KC_BOOTSTRAP_ADMIN_USERNAME": "synthetic-installer", "KC_BOOTSTRAP_ADMIN_PASSWORD": native.INSTALLER,
                "JAVA_OPTS_APPEND": "-Xms128m -Xmx384m -XX:MaxMetaspaceSize=192m -XX:ActiveProcessorCount=2",
                "IDENTITY_ACCOUNT_ADMIN_CLIENT_ID": "backend-account-admin",
                "ORISO_APP_BASE_URL": "https://otp-fixture.internal",
                "EMAIL_BRANDING_NAME": "OTP Fixture", "EMAIL_LEGAL_ORGANISATION_NAME": "Fixture Operator",
                "TASK_IDENTITY_MODEL": "FIVE_ACTORS", "ORISO_ACCOUNT_LIFECYCLE_ENABLED": "true",
                "ORISO_ACCOUNT_LIFECYCLE_REALM": native.REALM,
                "IDENTITY_ACCOUNT_CREATE_SERVICE_SUBJECT": native.SUBJECTS["ACCOUNT_CREATE"],
                "IDENTITY_ACCOUNT_ADMIN_SERVICE_SUBJECT": native.SUBJECTS["ACCOUNT_ADMIN"],
                "ORISO_TASK_CONTEXT_KEY": base64.b64encode(native.CONTEXT_KEY).decode(),
                "ORISO_ACCOUNT_LIFECYCLE_GROUPS": json.dumps({"/human-roles/" + k: v for k, v in native.HUMAN_GROUPS.items()})}
            for k, v in values.items():
                command.extend(["-e", k + "=" + v])
            for name, jar in jars.items():
                command.extend(["-v", str(jar) + ":/opt/keycloak/providers/" + name + ".jar:ro"])
            support.resources.docker(*command, native.IMAGE, "start-dev")
            metadata = owned.inspect("container", container)
            if ((metadata.get("Config",{}).get("Labels") or {}).get(owned.label_key) != run
                    or metadata.get("HostConfig",{}).get("Memory") != CONTAINER_MIB*1024*1024
                    or metadata.get("HostConfig",{}).get("MemorySwap") != CONTAINER_MIB*1024*1024):
                raise RuntimeError("Actual owned exact memory/no-swap container required")
            report["containerLimitAndNoSwapVerified"] = True
            port = metadata["NetworkSettings"]["Ports"]["8080/tcp"][0]["HostPort"]
            base = "http://127.0.0.1:" + port
            ready_end, installer = min(time.monotonic()+120, overall), None
            while time.monotonic() < ready_end:
                support.free_guard()
                try:
                    data = urlencode({"client_id": "admin-cli", "grant_type": "password",
                        "username": "synthetic-installer", "password": native.INSTALLER}).encode()
                    with urlopen(Request(base + "/realms/master/protocol/openid-connect/token", data=data,
                        headers={"Content-Type": "application/x-www-form-urlencoded"}), timeout=2) as response:
                        installer = json.load(response)["access_token"]
                    break
                except HTTPError as error:
                    error.close()
                    time.sleep(1)
                except (OSError, URLError, ValueError):
                    time.sleep(1)
            if not installer:
                raise RuntimeError("Finite native readiness unavailable")
            report["nativeResourcesStarted"] = True
            env.update(S1_NATIVE_BASE=base, S1_INSTALLER_BEARER=installer, S1_CHILD_EVIDENCE=str(out))
            report["executedGroupNames"].append("native-test")
            report["testExit"] = support.bounded([sys.executable, str(Path(__file__).resolve()), "--native-child"],
                root, env, private / "native-tests.log", 300, overall)
            receipt = json.loads((out / "native-observation.json").read_text())
            report.update(receipt)
            report["classification"] = native_classification(receipt)
            status = 0 if report["classification"] == "NATIVE_TRACER_GREEN_INCOMPLETE" else 1
    except Exception as failure:
        report["failureType"] = type(failure).__name__
        report["classification"] = ("BOUNDED_EXECUTION_OR_RESOURCE_REFUSAL" if isinstance(failure,
            (support.resources.ResourceRefusal, support.FixtureError)) else "SETUP_OR_INCOMPLETE_NO_PRODUCT_RED")
    finally:
        if owned is not None:
            try:
                report["ownedMemory"] = support.owned_memory_snapshot(owned, container)
                if not report.get("nativeResourcesStarted") or report.get("testExit"):
                    try:
                        report["safeNativeFailureFrames"] = native_failure_frames(support.resources.docker("logs","--tail","300",container))
                    except Exception as failure:
                        report["nativeFailureFramesUnavailable"] = type(failure).__name__
                report["cleanup"] = owned.cleanup()
            except Exception as failure:
                report["cleanupFailureType"] = type(failure).__name__
                report["classification"] = "RUNTIME_OR_CLEANUP_REFUSAL"
                status = 1
        if private is not None:
            stat = private.stat()
            if private.is_symlink() or (stat.st_dev,stat.st_ino,stat.st_uid) != private_owner:
                report["classification"] = "PRIVATE_LOG_OWNERSHIP_REFUSAL"
                status = 1
            else:
                shutil.rmtree(private)
                report["privateLogsRemoved"] = True
        after = {name: snapshot(folder) for name, folder in roots.items()}
        report["sourceAfter"] = after
        report["sourceStable"] = before == after and all(not git(folder,"status","--porcelain") for folder in roots.values())
        groups_file = out / "process-cleanup.jsonl"
        groups = [json.loads(row) for row in groups_file.read_text().splitlines()] if groups_file.exists() else []
        report["groups"] = groups
        report["groupsAbsent"] = named_groups_ok(groups,report.get("executedGroupNames"),report.get("plannedGroups"))
        try:
            support.memory_lease.check()
            report["finalWholeLeaseMemoryCheck"] = True
        except Exception as failure:
            report["finalWholeLeaseMemoryCheck"] = False
            report["classification"] = "FINAL_RESOURCE_REFUSAL"
            report["failureType"] = type(failure).__name__
            status = 1
        report["totalDeadlineRetained"] = time.monotonic() <= overall
        report["runtimeKnown"] = args.role == "user" or runtime_known(report.get("cleanup",[]))
        if not report["sourceStable"] or not report["totalDeadlineRetained"] or not report["groupsAbsent"] or not report["runtimeKnown"]:
            report["classification"] = "SOURCE_RESOURCE_OR_INCOMPLETE_REFUSAL"
            status = 1
        report["accepted"] = status == 0 and report["classification"] in ("USER_FOCUSED_GREEN", "NATIVE_TRACER_GREEN_INCOMPLETE")
        (out / "source-receipt.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({k:report.get(k) for k in ("role","classification","accepted","sourceStable","groupsAbsent","runtimeKnown","totalDeadlineRetained")}))
    return status


if __name__ == "__main__":
    if sys.argv[1:] == ["--native-child"]:
        raise SystemExit(child())
    raise SystemExit(main())
