"""Actual native impersonation cookie/code flow; credentials stay in memory."""

import base64
from http.cookiejar import CookieJar
from http.cookies import SimpleCookie
import hashlib
import json
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import (
    build_opener,
    HTTPCookieProcessor,
    HTTPRedirectHandler,
    HTTPSHandler,
    Request,
)
import uuid

from lifecycle_fixture import call, canonical, mac, REALM


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None


class ProtectedImpersonationCases:
    def test_actual_impersonated_native_session_cannot_issue_human_approval(self):
        # Empty cookie jar: only the native impersonation endpoint may establish SSO.
        jar = CookieJar()
        self.assertTrue(self.native_https_base.startswith("https://127.0.0.1:"))
        opener = build_opener(
            HTTPSHandler(context=self.native_tls_context),
            HTTPCookieProcessor(jar), NoRedirect(),
        )
        client = self.admin("GET", "/clients?clientId=protected-human-web")[0]
        client_id = client["id"]
        original = self.admin("GET", "/clients/" + client_id)
        redirect_uri = "http://protected-fixture.invalid/native-impersonation-proof"
        sessions_before = {
            s["id"]
            for s in self.admin("GET", "/users/" + self.human_subject + "/sessions")
        }
        before = self.admin("GET", "/users/count")
        observation = {"expectedApprovalStatus": 403}
        type(self).impersonation_observation = observation

        def native_request(method, route, body=None, bearer=None, form=False):
            headers = {}
            if bearer is not None:
                headers["Authorization"] = "Bearer " + bearer
            data = None if body is None else (
                urlencode(body).encode() if form else canonical(body)
            )
            if data is not None:
                headers["Content-Type"] = (
                    "application/x-www-form-urlencoded" if form else "application/json"
                )
            request = Request(
                self.native_https_base + route, data=data, headers=headers, method=method
            )
            if method == "GET":
                jar.add_cookie_header(request)
                cookie_header = request.get_header("Cookie") or ""
                observation["nativeIdentityCookieTransmitted"] = (
                    "KEYCLOAK_IDENTITY=" in cookie_header
                )
            try:
                response = opener.open(request, timeout=20)
            except HTTPError as failure:
                response = failure
            with response:
                return response.status, response.read(), response.headers

        try:
            changed = {**original, "redirectUris": [redirect_uri]}
            self.admin("PUT", "/clients/" + client_id, changed)
            status, raw, impersonation_headers = native_request(
                "POST",
                "/admin/realms/"
                + REALM
                + "/users/"
                + self.human_subject
                + "/impersonation",
                body={},
                bearer=self.installer,
            )
            observation["nativeImpersonationStatus"] = status
            self.assertEqual(200, status)
            observation["nativeHttpsVerified"] = True
            self.assertIsInstance(json.loads(raw), dict)
            offered = []
            for header in impersonation_headers.get_all("Set-Cookie") or []:
                parsed_cookie = SimpleCookie()
                parsed_cookie.load(header)
                if "KEYCLOAK_IDENTITY" in parsed_cookie:
                    offered.append(parsed_cookie["KEYCLOAK_IDENTITY"])
            host = urlsplit(self.native_https_base).hostname
            authorization_path = "/realms/" + REALM + "/protocol/openid-connect/auth"
            observation["nativeIdentityCookieOffered"] = len(offered) == 1
            observation["nativeIdentityCookieDomainMatchesRequest"] = any(
                not c["domain"]
                or host == c["domain"].lstrip(".")
                or host.endswith("." + c["domain"].lstrip("."))
                for c in offered
            )
            observation["nativeIdentityCookiePathMatchesAuthorization"] = any(
                authorization_path.startswith(c["path"] or "/") for c in offered
            )
            sessions_after = {
                s["id"]
                for s in self.admin("GET", "/users/" + self.human_subject + "/sessions")
            }
            created = sessions_after - sessions_before
            self.assertEqual(1, len(created))
            self.assertTrue(list(jar))
            observation["actualNativeImpersonationCreatedOneSession"] = True
            identities = [c for c in jar if c.name == "KEYCLOAK_IDENTITY"]
            observation["nativeIdentityCookiePresent"] = len(identities) == 1
            observation["nativeIdentityCookieSecure"] = any(
                c.secure for c in identities
            )
            self.assertTrue(observation["nativeIdentityCookieSecure"])
            verifier = uuid.uuid4().hex + uuid.uuid4().hex
            challenge = (
                base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
                .decode()
                .rstrip("=")
            )
            state = str(uuid.uuid4())
            query = urlencode(
                {
                    "client_id": "protected-human-web",
                    "redirect_uri": redirect_uri,
                    "response_type": "code",
                    "scope": "openid",
                    "state": state,
                    "code_challenge": challenge,
                    "code_challenge_method": "S256",
                    "prompt": "none",
                }
            )
            status, _, headers = native_request(
                "GET", "/realms/" + REALM + "/protocol/openid-connect/auth?" + query
            )
            observation["nativeAuthorizationStatus"] = status
            self.assertTrue(observation["nativeIdentityCookieTransmitted"])
            self.assertEqual(302, status)
            location = headers.get("Location")
            self.assertIsInstance(location, str)
            parsed = urlsplit(location)
            selected = urlsplit(redirect_uri)
            self.assertEqual(
                (selected.scheme, selected.netloc, selected.path),
                (parsed.scheme, parsed.netloc, parsed.path),
            )
            reply = parse_qs(parsed.query, strict_parsing=True)
            # Only fixed protocol categories; never persist Location/query values.
            errors = reply.get("error", [])
            if errors:
                categories = {
                    "login_required",
                    "interaction_required",
                    "consent_required",
                    "invalid_request",
                    "invalid_scope",
                    "access_denied",
                    "temporarily_unavailable",
                    "server_error",
                }
                observation["nativeAuthorizationError"] = (
                    errors[0]
                    if len(errors) == 1 and errors[0] in categories
                    else "OTHER"
                )
            self.assertNotIn("error", reply)
            self.assertEqual([state], reply.get("state"))
            self.assertEqual(1, len(reply.get("code", [])))
            status, token_raw, _ = native_request(
                "POST",
                "/realms/" + REALM + "/protocol/openid-connect/token",
                {
                    "grant_type": "authorization_code",
                    "client_id": "protected-human-web",
                    "code": reply["code"][0],
                    "redirect_uri": redirect_uri,
                    "code_verifier": verifier,
                },
                form=True,
            )
            observation["nativeCodeExchangeStatus"] = status
            self.assertEqual(200, status)
            token = json.loads(token_raw)
            bearer = token.get("access_token")
            self.assertIsInstance(bearer, str)
            # Reuse every existing current native human/client/grant/userinfo check.
            self.human(record=False, native_bearer=bearer)
            payload = bearer.split(".")[1]
            claims = json.loads(
                base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
            )
            self.assertIn(claims["sid"], created)
            observation["nativeCodeTokenUsesActualImpersonationSession"] = True
            observation["allCurrentNativeHumanPreconditionsPassed"] = True
            approval = str(uuid.uuid4())
            body = {"scope": self.scope()}
            expected_digest = mac(
                "protected-approval-request/v1",
                {
                    "request": body,
                    "issuerRealm": self.realm_id,
                    "issuerSubject": self.human_subject,
                },
            )
            status, response = call(
                self.base, "PUT", self.endpoint(approval), body, bearer
            )
            observation["actualApprovalStatus"] = status
            query = {
                "scopeDigest": None,
                "workflowId": body["scope"]["workflowId"],
                "inviteId": body["scope"]["inviteId"],
                "authorizationRevision": body["scope"]["authorizationRevision"],
                "attemptId": None,
                "approvalRequestDigest": expected_digest,
            }
            saved_status, saved = self.protected_machine_request(
                "status", approval, query
            )
            if status == 201:
                self.assertEqual("AUTHORIZED", response["state"])
                self.assertEqual(expected_digest, response["approvalRequestDigest"])
                receipt = response["approvalReceipt"]
                verified = self.verified_receipt(
                    receipt["receipt"],
                    "protected-approval-receipt/v1",
                    16384,
                    {
                        "approvalId",
                        "scopeDigest",
                        "issuerSubject",
                        "bindingVersion",
                        "profileVersion",
                        "validUntil",
                        "approvalRequestDigest",
                    },
                )
                self.assertEqual({**verified, "receipt": receipt["receipt"]}, receipt)
                self.assertEqual(self.human_subject, receipt["issuerSubject"])
                self.assertEqual(200, saved_status)
                self.assertEqual(response, saved)
                observation["signedApprovalNamesImpersonatedTarget"] = True
            else:
                self.assertEqual(404, saved_status)
                observation["approvalAbsentAfterRefusal"] = True
            self.assertEqual(before, self.admin("GET", "/users/count"))
            observation["noAccountCreated"] = True
            self.assertEqual(403, status)
        finally:
            jar.clear()
            self.admin("PUT", "/clients/" + client_id, original)
