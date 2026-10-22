"""Actual User/Redis caller, finite response-loss proxy; private values never leave memory."""
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
from urllib.error import HTTPError
from urllib.parse import parse_qs
from urllib.request import Request, urlopen
import lifecycle_fixture as native

CHECKS = ("childGroupInherited", "firstNative200Dropped", "secondNative200Forwarded",
          "exactCommandAfterLoss", "sameNativeSessionAfterLoss", "canonicalNativeAdmin", "javaFixtureGreen")
SUITE = "de.caritas.cob.userservice.api.service.auth.MagicLinkSessionNativeFixture"


def claims(raw):
    encoded = raw.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))


def run(fixture, target, tenant):
    checks = dict.fromkeys(CHECKS, False)
    fixture.paired_checks = checks
    endpoint = fixture.base + "/realms/" + native.REALM + "/protocol/openid-connect/token"
    packets = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            self.close_connection = True
            if self.path != endpoint:
                self.send_error(404)
                return
            size = self.headers.get("Content-Length", "")
            if not size.isdecimal() or not 0 < int(size) <= 65536:
                self.send_error(400)
                return
            raw = self.rfile.read(int(size))
            headers = {name: self.headers.get(name, "") for name in
                       ("Authorization", "X-ORISO-Task-Context", "Content-Type")}
            try:
                with urlopen(Request(endpoint, method="POST", data=raw, headers=headers), timeout=15) as response:
                    status, body = response.status, response.read()
            except HTTPError as failure:
                status, body = failure.code, failure.read()
                failure.close()
            if status == 200:
                actor = claims(headers["Authorization"].removeprefix("Bearer "))
                audiences = actor["aud"] if isinstance(actor["aud"], list) else [actor["aud"]]
                canonical = (actor.get("sub") == native.SUBJECTS["ACCOUNT_ADMIN"]
                    and actor.get("azp") == native.ACTORS["ACCOUNT_ADMIN"][0]
                    and actor.get("iss") == fixture.base + "/realms/" + native.REALM
                    and set(actor.get("realm_access", {}).get("roles", [])) == set(native.ACTORS["ACCOUNT_ADMIN"][1])
                    and set(audiences) == {"userservice", "oriso-account-lifecycle", "oriso-otp"}
                    and not actor.get("resource_access"))
                form = parse_qs(raw.decode(), strict_parsing=True)
                if set(form) != {"client_id", "grant_type", "oriso_magic_command"} or any(len(x) != 1 for x in form.values()):
                    raise RuntimeError("Fixed paired wire required")
                command = json.loads(form["oriso_magic_command"][0])
                if (set(command) != {"version", "workflowId", "targetUserId", "tenantId", "clientId", "expiresAt", "claimDigest"}
                        or command["targetUserId"] != target or command["tenantId"] != tenant):
                    raise RuntimeError("Fixed paired target required")
                returned = claims(json.loads(body)["access_token"])
                if returned.get("sub") != target or returned.get("azp") != "app" or returned.get("tenantId") != str(tenant):
                    raise RuntimeError("Fixed native result required")
                packets.append((raw, returned["sid"], canonical))
                if len(packets) == 1:
                    checks["firstNative200Dropped"] = True
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.flush()
                    self.connection.shutdown(socket.SHUT_RDWR)
                    self.connection.close()
                    return
                checks["secondNative200Forwarded"] = len(packets) == 2
                checks["exactCommandAfterLoss"] = len(packets) == 2 and packets[0][0] == raw
                checks["sameNativeSessionAfterLoss"] = len(packets) == 2 and packets[0][1] == returned["sid"]
                checks["canonicalNativeAdmin"] = all(packet[2] is True for packet in packets)
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    # Suppress BaseServer's raw exception/traceback hook; the finite Java/XML/booleans carry outcome.
    server.handle_error = lambda *args: None
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    source = Path(os.environ["S1_USER_SOURCE"])
    env = {**os.environ, "S1_REALM_NAME": native.REALM, "S1_REALM_ID": fixture.realm_id,
           "S1_CONTEXT_KEY": base64.b64encode(native.CONTEXT_KEY).decode(),
           "S1_TARGET_USER": target, "S1_TARGET_TENANT": str(tenant),
           "S1_PROXY_PORT": str(server.server_address[1]),
           "S1_ACTOR_BINDINGS": json.dumps({actor: {"clientId": native.ACTORS[actor][0],
               "subject": native.SUBJECTS[actor], "secret": "synthetic-lifecycle-" + actor} for actor in native.ACTORS})}
    command = [str(source / "mvnw"), "-B", "-ntp", "-q", "-Dtest=" + SUITE,
               "-DfailIfNoTests=true", "-DforkCount=1", "-DreuseForks=false",
               "-DargLine=-Xmx384m -XX:MaxMetaspaceSize=192m -XX:ActiveProcessorCount=2", "surefire:test"]
    try:
        with (Path(os.environ["S1_PAIR_PRIVATE"]) / "paired-user.log").open("wb") as private:
            process = subprocess.Popen(command, cwd=source, env=env, stdout=private, stderr=subprocess.STDOUT)
            checks["childGroupInherited"] = os.getpgid(process.pid) == os.getpgrp()
            if not checks["childGroupInherited"]:
                process.kill()
                process.wait(timeout=5)
                raise RuntimeError("Owned paired process group required")
            try:
                fixture.paired_exit = process.wait(timeout=120)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
                fixture.paired_exit = 124
                raise RuntimeError("Finite paired fixture deadline")
        checks["javaFixtureGreen"] = fixture.paired_exit == 0
        fixture.assertEqual(0, fixture.paired_exit, "Actual private Redis/native caller must complete")
        fixture.assertTrue(all(checks.values()))
    finally:
        fixture.paired_export = {"checks": checks, "exit": getattr(fixture, "paired_exit", None)}
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)
        if worker.is_alive():
            raise RuntimeError("Owned paired proxy thread remains")
