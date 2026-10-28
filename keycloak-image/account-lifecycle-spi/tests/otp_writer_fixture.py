"""One real native SMTP writer and cancellation, observed by a separate disposable SPI."""
import concurrent.futures
import hashlib
import json
import os
import re
from pathlib import Path
import subprocess
import tempfile
import threading
import time

PREFIX = "ORISO_PROOF_OTP_WRITER_V1 "
FACTS = {"schema", "phase", "actualNativeWriterTransaction", "exactPrivateSendingOrigin",
         "runtimeH2Pinned", "exactNativeDefaultDelegate", "cancelBlockedByCapturedWriter",
         "defaultSmtpReturned", "writerCommitted", "observerFailed"}


def delegate_rows(output):
    rows = []
    prefix = "ORISO_PROOF_OTP_DELEGATE_V1 "
    for line in output.splitlines():
        if prefix not in line:
            continue
        row = json.loads(line.split(prefix, 1)[1])
        if (set(row) != {"schema", "phase", "nativeDefaultPresent", "nativeDefaultClassExact"}
                or row["schema"] != 1
                or row["phase"] not in {"CONSTRUCTION_ENTERED", "CONSTRUCTED", "VALIDATED", "VALIDATION_FAILED", "SEND_ADDRESS_ENTERED", "CAPTURE_ENTERED",
                    "CAPTURE_TRANSACTION_VERIFIED", "CAPTURE_SENDING_VERIFIED",
                    "CAPTURE_BOOTSTRAP_VERIFIED", "CAPTURE_ATTEMPT_VERIFIED", "CAPTURE_REJECTED"}
                or type(row["nativeDefaultPresent"]) is not bool
                or type(row["nativeDefaultClassExact"]) is not bool):
            raise AssertionError("Closed native delegate observation required")
        rows.append(row)
    if len(rows) > 10000:
        raise AssertionError("Native delegate observation exceeds fixture bound")
    return rows


def delegate_observations(fixture):
    result = subprocess.run(["docker", "logs", fixture.name], check=True,
                            capture_output=True, text=True, timeout=10)
    rows = delegate_rows(result.stdout + result.stderr)
    return {"phaseCounts": {phase: sum(row["phase"] == phase for row in rows) for phase in sorted({row["phase"] for row in rows})},
            "totalEvents": len(rows), "sampleTruncated": len(rows) > 16, "firstEvents": rows[:16],
            "nativeDefaultPresent": any(row["nativeDefaultPresent"] for row in rows),
            "nativeDefaultClassExact": any(row["nativeDefaultClassExact"] for row in rows)}


def setup(fixture):
    supplied = os.environ.get("OTP_WRITER_PROOF_JAR")
    fixture.writer_enabled = supplied is not None
    if supplied is None:
        return
    path = Path(supplied).resolve()
    runner = Path(os.environ["RUNNER_TEMP"]).resolve()
    if path.parent != runner or path.name != "oriso-proof-otp-writer-companion.jar" or not path.is_file():
        raise AssertionError("Exact disposable native writer companion required")
    fixture.writer_jar = path
    fixture.writer_jar_sha = hashlib.sha256(path.read_bytes()).hexdigest()
    directory = tempfile.TemporaryDirectory(prefix="oriso-otp-writer-", dir=runner)
    fixture.addClassCleanup(directory.cleanup)
    fixture.writer_control = Path(directory.name)
    fixture.writer_control.chmod(0o755)


def handler(base):
    class BarrierHandler(base):
        def handle(self):
            self.wfile.write(b"220 fixture SMTP ready\r\n")
            while True:
                line = self.rfile.readline(8192)
                if not line:
                    return
                verb = line.split(b" ", 1)[0].strip().upper()
                if verb == b"DATA":
                    self.wfile.write(b"354 message\r\n")
                    body = []
                    while True:
                        line = self.rfile.readline(65536)
                        if line in (b".\r\n", b"", b".\n"):
                            break
                        body.append(line)
                        if sum(map(len, body)) > 1024 * 1024:
                            raise AssertionError("Synthetic SMTP data exceeds fixture bound")
                    self.server.messages.append(b"".join(body))
                    if getattr(self.server, "writer_armed", False):
                        self.server.writer_entered.set()
                        if not self.server.writer_release.wait(3.2):
                            self.server.writer_timed_out = True
                            self.wfile.write(b"451 proof barrier expired\r\n")
                            continue
                    self.wfile.write(b"451 synthetic uncertain delivery\r\n" if getattr(
                        self.server, "reject_after_data", False) else b"250 accepted\r\n")
                elif verb == b"QUIT":
                    self.wfile.write(b"221 bye\r\n")
                    return
                else:
                    self.wfile.write(b"250 accepted\r\n")
    return BarrierHandler


def launch(fixture, arguments, image):
    if not getattr(fixture, "writer_enabled", False):
        return arguments
    result = arguments.copy()
    index = result.index(image)
    result[index:index] = ["-v", str(fixture.writer_jar) + ":/opt/keycloak/providers/oriso-proof-otp-writer-companion.jar:ro",
                           "-v", str(fixture.writer_control) + ":/opt/keycloak/proof-otp-writer:ro"]
    result.append("--spi-email-sender--provider=oriso-proof-otp-writer")
    return result


def wait_rows(output):
    prefix = "ORISO_PROOF_OTP_WAIT_V1 "
    fields = {"schema", "rowCount", "nativeBlockedState", "capturedBlockerMatches", "otherSession",
              "realmTable", "forUpdate", "realmParameterSuffix", "exactOriginalGrammar",
              "selectStatement", "onlyRealmTable", "singlePrimaryKeyPredicate", "onlyForUpdateAndExactRealmBind"}
    rows = []
    for line in output.splitlines():
        if prefix not in line:
            continue
        row = json.loads(line.split(prefix, 1)[1])
        if (set(row) != fields or row["schema"] != 1 or type(row["rowCount"]) is not int
                or not 0 <= row["rowCount"] <= 1000
                or any(type(row[k]) is not bool for k in fields - {"schema", "rowCount"})):
            raise AssertionError("Closed finite native wait observation required")
        rows.append(row)
    if len(rows) > 1:
        raise AssertionError("Exactly one bounded native wait sample permitted")
    return rows


def wait_observations(fixture):
    output = subprocess.run(["docker", "logs", fixture.name], check=True, capture_output=True, text=True, timeout=10)
    return wait_rows(output.stdout + output.stderr)


def sql_template(output):
    prefix = "ORISO_PROOF_OTP_SQL_TEMPLATE_V1 "
    rows = [json.loads(line.split(prefix, 1)[1]) for line in output.splitlines() if prefix in line]
    if len(rows) != 1 or set(rows[0]) != {"schema", "template"} or rows[0]["schema"] != 1:
        raise AssertionError("Exactly one sanitized native SQL template required")
    value = rows[0]["template"]
    if (not isinstance(value, str) or not 1 <= len(value) <= 16384
            or not value.startswith("select ") or " from realm " not in value
            or not re.fullmatch(r"[a-z0-9_ .,*()=?{}:<>'+\-/]+", value.replace("<BOUND_REALM>", "bound"))
            or re.search(r"'(?!<BOUND_REALM>')[^']*'", value)
            or "--" in value or "/*" in value):
        raise AssertionError("Closed sanitized native SQL template required")
    return value


def observations(fixture):
    output = subprocess.run(["docker", "logs", fixture.name], check=True, capture_output=True, text=True, timeout=10)
    rows = []
    for line in (output.stdout + output.stderr).splitlines():
        if PREFIX not in line:
            continue
        row = json.loads(line.split(PREFIX, 1)[1])
        if set(row) != FACTS or row["schema"] != 1 or row["phase"] not in {"ENTERED", "BLOCKED", "SMTP_RETURNED", "COMMITTED", "ROLLED_BACK", "FAILED"}:
            raise AssertionError("Closed native writer observation required")
        if any(type(row[k]) is not bool for k in FACTS - {"schema", "phase"}):
            raise AssertionError("Native writer observation must contain only finite booleans")
        rows.append(row)
    if len(rows) > 8:
        raise AssertionError("Native writer observation exceeds one-writer bound")
    return rows


def future_observation(future):
    result = {"completed": future.done(), "httpStatus": None}
    if future.done() and not future.cancelled() and future.exception() is None:
        value = future.result()
        if isinstance(value, tuple) and len(value) == 2 and type(value[0]) is int and 100 <= value[0] <= 599:
            result["httpStatus"] = value[0]
    return result


def concurrent_start(fixture, control, start_request, cancel_request, observed):
    if not fixture.writer_enabled or (fixture.writer_control / "control.json").exists():
        raise AssertionError("Exactly one armed real writer required")
    mail = fixture.mail
    mail.writer_entered, mail.writer_release = threading.Event(), threading.Event()
    mail.writer_timed_out, mail.writer_armed = False, True
    path = fixture.writer_control / "control.json"
    path.write_text(json.dumps(control, sort_keys=True)); path.chmod(0o644)
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=2)
    writer = pool.submit(start_request)
    cancellation = None
    try:
        if not mail.writer_entered.wait(5):
            observed["inflightFixedPhase"] = "SMTP_BARRIER_NOT_ENTERED"
            observed["inflightWriterFuture"] = future_observation(writer)
            raise AssertionError("Real native SMTP writer did not reach owned barrier")
        cancellation = pool.submit(cancel_request)
        deadline = time.monotonic() + 2.0
        matched = False
        while time.monotonic() < deadline:
            rows = observations(fixture)
            if any(row["phase"] == "FAILED" or row["observerFailed"] for row in rows):
                raise AssertionError("Native writer observer failed before lock witness")
            if any(row["phase"] == "BLOCKED" and row["cancelBlockedByCapturedWriter"] for row in rows):
                matched = True
                break
            time.sleep(0.025)
        if not matched or cancellation.done() or mail.writer_timed_out:
            observed["inflightFixedPhase"] = "CANCEL_WAIT_WITNESS_MISSING"
            observed["inflightCancellationFutureBeforeRelease"] = future_observation(cancellation)
            raise AssertionError("Actual cancel must be blocked by the captured native SMTP writer")
        observed["inflightCancelBlockedByActualWriter"] = True
    finally:
        # Release the SMTP owner before waiting for either HTTP worker, including failed setup.
        mail.writer_release.set()
        pool.shutdown(wait=True, cancel_futures=False)
        mail.writer_armed = False
        observed["inflightWriterFutureAfterRelease"] = future_observation(writer)
        observed["inflightCancellationFutureAfterRelease"] = None if cancellation is None else future_observation(cancellation)
        observed["inflightNativeWriterEventsAfterRelease"] = observations(fixture)
        observed["inflightNativeWaitSample"] = wait_observations(fixture)
        output = subprocess.run(["docker", "logs", fixture.name], check=True,
                                capture_output=True, text=True, timeout=10)
        observed["inflightSanitizedSqlTemplate"] = sql_template(output.stdout + output.stderr)
    ready = writer.result(timeout=1)
    cancelled = cancellation.result(timeout=1) if cancellation is not None else None
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        rows = observations(fixture)
        if any(row["phase"] == "COMMITTED" and row["writerCommitted"] and row["defaultSmtpReturned"] for row in rows):
            break
        time.sleep(0.025)
    else:
        raise AssertionError("Actual native sender transaction commit was not observed")
    if any(row["observerFailed"] or row["phase"] in {"ROLLED_BACK", "FAILED"} for row in rows):
        raise AssertionError("Native writer transaction or observer failed")
    observed["inflightWriterEvents"] = rows
    observed["inflightWriterCommittedAfterDefaultSmtp"] = True
    observed["inflightBarrierDidNotExpire"] = not mail.writer_timed_out
    observed["inflightCompanionJarStable"] = hashlib.sha256(fixture.writer_jar.read_bytes()).hexdigest() == fixture.writer_jar_sha
    return ready, cancelled
