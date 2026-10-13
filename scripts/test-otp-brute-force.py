#!/usr/bin/env python3
"""Probe OTP accounting in an isolated Keycloak image with synthetic users and SMTP.

Requires Docker and Python's standard library. Never connects to a live realm.
--provider-jar replaces only ORISO's SPI in the exact baseline image for RED/GREEN.
Browser tests submit the real OIDC form flow over HTTP, not a mocked authenticator.
"""
import argparse
import concurrent.futures
import email
import hashlib
import hmac
import http.cookiejar
import json
import re
import socketserver
import subprocess
import threading
import time
import struct
import urllib.error
import urllib.parse
import urllib.request
import uuid
from html import unescape
from pathlib import Path

PASSWORD = "Synthetic-probe-password-2026!"
ADMIN_PASSWORD = "Synthetic-admin-password-2026!"
REALM = "otp-accounting-probe"
MAIL = []
RESULTS = []


class SmtpSink(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"220 synthetic.local ESMTP\r\n")
        while line := self.rfile.readline():
            command = line.decode(errors="replace").strip().upper()
            if command.startswith(("EHLO", "HELO")):
                self.wfile.write(b"250 synthetic.local\r\n")
            elif command == "DATA":
                self.wfile.write(b"354 continue\r\n")
                body = []
                while (part := self.rfile.readline()) not in (b".\r\n", b""):
                    body.append(part)
                MAIL.append(b"".join(body))
                self.wfile.write(b"250 accepted\r\n")
            elif command == "QUIT":
                self.wfile.write(b"221 bye\r\n")
                break
            else:
                self.wfile.write(b"250 OK\r\n")


class BrowserRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Stop at the synthetic application's callback; no real application runs there.
        if urllib.parse.urlparse(newurl).path == "/callback":
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def docker(*args):
    return subprocess.check_output(["docker", *args], stderr=subprocess.PIPE).decode().strip()


def check(name, actual, expected):
    RESULTS.append({"test": name, "actual": actual, "expected": expected})
    if actual != expected:
        raise AssertionError(f"{name}: expected {expected!r}, observed {actual!r}")


def code_from_last_mail():
    message = email.message_from_bytes(MAIL[-1])
    bodies = [part.get_payload(decode=True).decode(errors="replace")
              for part in message.walk() if part.get_content_type() in ("text/plain", "text/html")]
    codes = re.findall(r"(?<!\d)\d{6}(?!\d)", "\n".join(bodies))
    if not codes:
        raise AssertionError("synthetic mail did not contain a code")
    return codes[0]


def totp(secret):
    digest = hmac.new(secret.encode(), struct.pack(">Q", int(time.time()) // 30), hashlib.sha1).digest()
    offset = digest[-1] & 15
    return str((struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7fffffff) % 1000000).zfill(6)


def run(args, smtp_port):
    passed = False
    name = "otp-accounting-" + uuid.uuid4().hex[:12]
    command = ["run", "-d", "--platform", args.platform, "--name", name,
               "-p", "127.0.0.1::8080", "-e", "KC_BOOTSTRAP_ADMIN_USERNAME=probe-admin",
               "-e", "KC_BOOTSTRAP_ADMIN_PASSWORD=" + ADMIN_PASSWORD,
               "-e", "ORISO_APP_BASE_URL=http://localhost:8080",
               "-e", "EMAIL_BRANDING_NAME=Synthetic", "-e", "EMAIL_LEGAL_ORGANISATION_NAME=Synthetic",
               "-e", "KC_SPI_BRUTE_FORCE_PROTECTOR__DEFAULT_BRUTE_FORCE_DETECTOR__ALLOW_CONCURRENT_REQUESTS=false"]
    if args.provider_jar:
        command += ["-v", str(args.provider_jar.resolve()) +
                    ":/opt/keycloak/providers/keycloak-otp-config-spi-1.0-SNAPSHOT-keycloak.jar:ro"]
    command += [args.image, "start-dev", "--db=dev-file", "--http-relative-path=/auth"]
    try:
        docker(*command)
        port = docker("port", name, "8080/tcp").split(":")[-1]
        base = "http://127.0.0.1:" + port + "/auth"
        admin_token = None

        def request(path, data=None, token=None, method=None):
            headers = {}
            if isinstance(data, dict):
                data = json.dumps(data).encode()
                headers["Content-Type"] = "application/json"
            if token:
                headers["Authorization"] = "Bearer " + token
            try:
                with urllib.request.urlopen(urllib.request.Request(base + path, data, headers, method=method), timeout=30) as res:
                    raw = res.read()
                    return res.status, json.loads(raw) if raw else None
            except urllib.error.HTTPError as error:
                return error.code, json.loads(error.read())

        def login(user, password=PASSWORD, realm=REALM, client="probe-client", otp=None):
            form = {"grant_type": "password", "client_id": client, "username": user, "password": password}
            if otp is not None:
                form["otp"] = otp
            return request("/realms/" + realm + "/protocol/openid-connect/token", urllib.parse.urlencode(form).encode())

        def admin(path, data=None, method=None):
            nonlocal admin_token
            if admin_token is None:
                admin_token = login("probe-admin", ADMIN_PASSWORD, "master", "admin-cli")[1]["access_token"]
            status, body = request("/admin/realms/" + REALM + path, data, admin_token, method)
            if status == 401:
                admin_token = None
                return admin(path, data, method)
            return status, body

        for _ in range(900):
            try:
                status, body = login("probe-admin", ADMIN_PASSWORD, "master", "admin-cli")
                if status == 200:
                    admin_token = body["access_token"]
                    break
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(1)
        else:
            raise AssertionError("isolated Keycloak did not start within 900 seconds")

        realm = json.loads((Path(__file__).resolve().parents[1] / "realm.json").read_text())
        for field in ("id", "users", "clients", "clientScopes", "roles", "defaultRole", "defaultRoles",
                      "defaultDefaultClientScopes", "defaultOptionalClientScopes", "smtpServer", "identityProviders",
                      "identityProviderMappers", "passwordPolicy"):
            realm.pop(field, None)
        realm.update(realm=REALM, bruteForceProtected=True, permanentLockout=False,
                     maxTemporaryLockouts=0, maxSecondaryAuthFailures=0, failureFactor=15,
                     bruteForceStrategy="MULTIPLE", waitIncrementSeconds=60, maxFailureWaitSeconds=900,
                     maxDeltaTimeSeconds=43200, quickLoginCheckMilliSeconds=1000, minimumQuickLoginWaitSeconds=5,
                     smtpServer={"host": "host.docker.internal", "port": str(smtp_port),
                                 "from": "sender@synthetic.invalid", "auth": "false", "ssl": "false", "starttls": "false"},
                     clients=[{"clientId": "probe-client", "enabled": True, "publicClient": True,
                               "directAccessGrantsEnabled": True, "standardFlowEnabled": True,
                               "redirectUris": ["http://localhost/callback"]}],
                     roles={"realm": [{"name": "otp-config-admin"}]}, users=[])
        for user in ("technical", "email-user", "browser-user", "app-user"):
            realm["users"].append({"username": user, "firstName": "Synthetic", "lastName": "Probe",
                                   "email": user + "@synthetic.invalid", "emailVerified": True, "enabled": True,
                                   "realmRoles": ["otp-config-admin"] if user == "technical" else [],
                                   "credentials": [{"type": "password", "value": PASSWORD, "temporary": False}]})
        check("synthetic-realm-created", request("/admin/realms", realm, admin_token)[0], 201)
        ids = {u["username"]: u["id"] for u in admin("/users")[1]}

        def counter(user):
            time.sleep(.2)
            body = admin("/attack-detection/brute-force/users/" + ids[user])[1]
            return {k: body[k] for k in ("numFailures", "numSecondaryAuthFailures", "disabled")}

        service_token = login("technical")[1]["access_token"]
        for user in ("email-user", "browser-user"):
            path = "/realms/" + REALM + "/otp-config/"
            check("email-setup-mail-" + user, request(path + "send-verification-mail/" + user,
                  {"email": user + "@synthetic.invalid"}, service_token, "PUT")[0], 200)
            check("email-setup-activate-" + user, request(path + "setup-otp-mail/" + user,
                  {"initialCode": code_from_last_mail()}, service_token, "POST")[0], 201)

        status, body = login("email-user")
        check("email-prompt-status", status, 400)
        check("email-prompt-protocol", (body["error_description"], body["otpType"], body["resendAvailableInSeconds"]), ("Missing totp", "EMAIL", 30))
        initial_code = code_from_last_mail()
        check("email-prompt-not-a-failure", counter("email-user")["numFailures"], 0)
        mail_count = len(MAIL)
        for _ in range(16):
            check("cooldown-prompt-status", login("email-user")[0], 400)
        check("cooldown-kept-code-and-mail", len(MAIL), mail_count)
        check("repeated-prompt-not-a-failure", counter("email-user")["numFailures"], 0)
        check("wrong-email-OTP-status", login("email-user", otp="000000" if initial_code != "000000" else "111111")[0], 401)
        check("wrong-email-OTP-counted", counter("email-user")["numFailures"], 1)
        time.sleep(1.1)
        check("correct-email-OTP-status", login("email-user", otp=initial_code)[0], 200)
        check("successful-email-OTP-clears-counters", counter("email-user"), {"numFailures": 0, "numSecondaryAuthFailures": 0, "disabled": False})
        check("used-email-OTP-rejected", login("email-user", otp=initial_code)[0], 401)

        # Email cap and mail failure remain challenges. Accelerate only the SMTP cooldown
        # here; account protection retains candidate values throughout.
        config = next(c for c in realm["authenticatorConfig"] if c["alias"] == "email-otp-config")
        config["config"]["resendCooldownSeconds"] = "0"
        check("local-email-cooldown-config", admin("/authentication/config/" + config["id"], config, "PUT")[0], 204)
        for _ in range(4):
            check("permitted-mail-status", login("email-user")[0], 400)
        status, body = login("email-user")
        check("email-cap-status", status, 429)
        check("email-cap-does-not-count", counter("email-user")["numFailures"], 1)
        last_code = code_from_last_mail()
        barrier = threading.Barrier(2)
        def same_otp(_):
            barrier.wait()
            return login("email-user", otp=last_code)[0]
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            statuses = sorted(pool.map(same_otp, range(2)))
            check("one-code-concurrent-single-success-clean-rejection",
                  statuses in ([200, 400], [200, 401]), True)
            RESULTS.append({"test": "one-code-concurrent-statuses", "actual": statuses})
        check("concurrent-used-code-rejected", login("email-user", otp=last_code)[0], 401)

        service_token = login("technical")[1]["access_token"]
        # The SPI accepts Keycloak raw secret bytes, not the QR code Base32 encoding.
        app_secret = "SyntheticRawSecretForOtpProbe2026"
        setup_interval = int(time.time()) // 30
        check("app-OTP-setup", request("/realms/" + REALM + "/otp-config/setup-otp/app-user",
              {"secret": app_secret, "initialCode": totp(app_secret)}, service_token, "PUT")[0], 201)
        for _ in range(16):
            status, body = login("app-user")
            check("app-OTP-prompt-status", status, 400)
            check("app-OTP-prompt-type", body["otpType"], "APP")
        check("app-OTP-prompt-not-a-failure", counter("app-user")["numFailures"], 0)
        valid = totp(app_secret)
        check("wrong-app-OTP-rejected", login("app-user", otp="000000" if valid != "000000" else "111111")[0], 400)
        check("wrong-app-OTP-counted", counter("app-user")["numFailures"], 1)
        time.sleep(max(1.1, (setup_interval + 1) * 30 + 1 - time.time()))
        check("correct-app-OTP", login("app-user", otp=totp(app_secret))[0], 200)
        check("app-OTP-success-clears-counters", counter("app-user")["numFailures"], 0)

        def browser_flow():
            opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()), BrowserRedirects())
            url = base + "/realms/" + REALM + "/protocol/openid-connect/auth?" + urllib.parse.urlencode({
                "client_id": "probe-client", "response_type": "code", "scope": "openid",
                "redirect_uri": "http://localhost/callback", "state": "synthetic", "nonce": uuid.uuid4().hex})
            return opener, opener.open(url).read().decode()

        def form_submit(opener, html, values):
            match = re.search(r'<form[^>]+action="([^"]+)"', html)
            if match is None:
                raise AssertionError("real browser flow has no form action")
            action = unescape(match.group(1))
            try:
                with opener.open(action, urllib.parse.urlencode(values).encode()) as response:
                    return response.status, response.read().decode(), None
            except urllib.error.HTTPError as error:
                return error.code, error.read().decode(), error.headers.get("Location")

        opener, html = browser_flow()
        status, html, _ = form_submit(opener, html, {"username": "browser-user", "password": PASSWORD})
        check("browser-email-prompt-status", status, 200)
        check("browser-email-prompt-not-a-failure", counter("browser-user")["numFailures"], 0)
        code = code_from_last_mail()
        status, html, _ = form_submit(opener, html, {"otp": "000000" if code != "000000" else "111111"})
        check("browser-wrong-code-retry-form", status, 200)
        check("browser-wrong-code-counted", counter("browser-user")["numFailures"], 1)
        status, _, callback = form_submit(opener, html, {"otp": code})
        check("browser-correct-OTP-code-redirect", status, 302)
        check("browser-issues-authorization-code", "code=" in (callback or ""), True)
        check("browser-success-clears-counters", counter("browser-user")["numFailures"], 0)
        # Only this synthetic browser credential gets a two-second lifetime.
        # The replacement receives the normal lifetime before the expired submission.
        config["config"]["ttl"] = "2"
        check("local-expired-code-fixture", admin("/authentication/config/" + config["id"], config, "PUT")[0], 204)
        opener, html = browser_flow()
        status, html, _ = form_submit(opener, html, {"username": "browser-user", "password": PASSWORD})
        check("expired-browser-prompt", status, 200)
        expired_code = code_from_last_mail()
        time.sleep(3)
        config["config"]["ttl"] = "900"
        check("local-replacement-lifetime", admin("/authentication/config/" + config["id"], config, "PUT")[0], 204)
        mail_count = len(MAIL)
        status, html, _ = form_submit(opener, html, {"otp": expired_code})
        check("expired-browser-retry-form", status, 200)
        check("expired-browser-code-counted", counter("browser-user")["numFailures"], 1)
        check("expired-browser-code-replacement-mail", len(MAIL), mail_count + 1)
        replacement_code = code_from_last_mail()
        status, _, callback = form_submit(opener, html, {"otp": replacement_code})
        check("replacement-browser-code-success", status, 302)
        check("replacement-browser-success-clears-counters", counter("browser-user")["numFailures"], 0)
        broken_smtp = dict(realm["smtpServer"], host="localhost", port="1")
        check("local-SMTP-failure-fixture", admin("", {"smtpServer": broken_smtp}, "PUT")[0], 204)
        check("SMTP-failure-status", login("browser-user")[0], 500)
        check("SMTP-failure-not-a-credential-failure", counter("browser-user")["numFailures"], 0)

        for attempt in range(1, 16):
            time.sleep(1.05)
            check("wrong-password-refused-" + str(attempt), login("technical", password="wrong-synthetic-password")[0], 400)
        check("wrong-password-still-locks", counter("technical"), {"numFailures": 15, "numSecondaryAuthFailures": 0, "disabled": True})
        check("correct-password-during-lock-refused", login("technical")[0], 400)
        check("master-admin-escape", login("probe-admin", ADMIN_PASSWORD, "master", "admin-cli")[0], 200)
        check("admin-unlock", admin("/attack-detection/brute-force/users/" + ids["technical"], method="DELETE")[0], 204)
        barrier = threading.Barrier(20)
        def parallel(_):
            barrier.wait()
            return login("technical")[0]
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as pool:
            statuses = list(pool.map(parallel, range(20)))
        check("default-detector-clean-concurrent-rejection", set(statuses), {200, 400})
        check("default-detector-no-counter-for-concurrency", counter("technical")["numFailures"], 0)
        passed = True
    finally:
        if RESULTS:
            print(json.dumps({"image": args.image, "providerOverlay": bool(args.provider_jar), "passed": passed, "results": RESULTS}, default=list, indent=2), flush=True)
        subprocess.run(["docker", "rm", "-f", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--provider-jar", type=Path)
    parser.add_argument("--platform", default="linux/amd64")
    args = parser.parse_args()
    with socketserver.ThreadingTCPServer(("127.0.0.1", 0), SmtpSink) as smtp:
        threading.Thread(target=smtp.serve_forever, daemon=True).start()
        try:
            run(args, smtp.server_address[1])
        finally:
            smtp.shutdown()
