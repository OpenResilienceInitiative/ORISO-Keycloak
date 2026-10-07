#!/usr/bin/env python3
"""Real HTTP permission/creation contract in a disposable synthetic Keycloak only."""

from task_command_fixtures import (
    canonical,
    proof,
    seed_legacy,
    verify_native_subject_and_scope,
    verify_projected_account,
    verify_platform_self_service,
    verify_origin_workflows,
    verify_otp_subject_binding,
    verify_smtp_revisions,
)

from task_inactivity_fixtures import verify_inventory, verify_lifecycle_effects

import concurrent.futures
import argparse
import base64
import json
import os
import subprocess
import time
import urllib.request
import urllib.error
import urllib.parse
import uuid

KEY = base64.b64encode(os.urandom(32)).decode()
MAINT_KEY = base64.b64encode(os.urandom(32)).decode()
CLIENTS = {
    "backend-account-provisioning": ["account-provisioning", "account-read"],
    "backend-account-maintenance": ["account-maintenance", "account-read"],
    "backend-account-otp": ["otp-config-admin"],
    "backend-smtp-sync": ["smtp-sync"],
    "backend-consultant-import": ["consultant-import"],
}


def main(image, legacy_otp=False):
    name = "task-command-probe-" + uuid.uuid4().hex[:10]
    realm = "task-probe"
    checks = []

    def docker(*args):
        return subprocess.check_output(["docker", *args], stderr=subprocess.PIPE, text=True).strip()

    def check(label, status, expected):
        if status != expected:
            raise AssertionError(f"{label}: expected {expected}, got {status}")
        checks.append(label)

    try:
        docker(
            "run",
            "-d",
            "--name",
            name,
            "-p",
            "127.0.0.1::8080",
            "-e",
            "ORISO_LEGACY_OTP_COMPATIBILITY=" + str(legacy_otp).lower(),
            "-e",
            "KC_BOOTSTRAP_ADMIN_USERNAME=synthetic-admin",
            "-e",
            "KC_BOOTSTRAP_ADMIN_PASSWORD=Synthetic-master-2026!",
            "-e",
            "ORISO_APP_BASE_URL=http://localhost",
            "-e",
            "EMAIL_BRANDING_NAME=Synthetic",
            "-e",
            "EMAIL_LEGAL_ORGANISATION_NAME=Synthetic",
            "-e",
            "ORISO_IDENTITY_DUMMY_EMAIL_SUFFIX=@beratungcaritas.de",
            "-e",
            "ORISO_PROVISIONING_ORIGIN_KEY=" + KEY,
            "-e",
            "ORISO_MAINTENANCE_ORIGIN_KEY=" + MAINT_KEY,
            "-e",
            "JAVA_OPTS_KC_HEAP=-Xms128m -Xmx768m",
            "-e",
            "JAVA_OPTS_APPEND=-XX:ActiveProcessorCount=2",
            image,
            "start",
            "--optimized",
            "--hostname-strict=false",
            "--http-enabled=true",
        )
        base = "http://127.0.0.1:" + docker("port", name, "8080/tcp").split(":")[-1]

        def request(path, body=None, token=None, method=None, origin=None):
            headers = {}
            if isinstance(body, (dict, list)):
                body = canonical(body).encode()
                headers["Content-Type"] = "application/json"
            if isinstance(body, bytes) and "Content-Type" not in headers:
                headers["Content-Type"] = "application/x-www-form-urlencoded"
            if token:
                headers["Authorization"] = "Bearer " + token
            if origin:
                headers["X-ORISO-Origin-Authorization"] = origin
            try:
                with urllib.request.urlopen(
                    urllib.request.Request(base + path, body, headers, method=method),
                    timeout=30,
                ) as r:
                    raw = r.read()
                    return r.status, json.loads(raw) if raw else None
            except urllib.error.HTTPError as e:
                raw = e.read()
                try:
                    data = json.loads(raw) if raw else None
                except ValueError:
                    data = None
                return e.code, data

        def authorized(path, body, actor, method, operation, target, key, **origin):
            return request(
                path,
                None if method in (None, "GET", "DELETE") else body,
                tokens[actor],
                method,
                proof(key, operation, target, body, actor, subjects[actor], **origin),
            )

        def grant(r, form):
            return request(
                "/realms/" + r + "/protocol/openid-connect/token",
                urllib.parse.urlencode(form).encode(),
            )

        for _ in range(180):
            try:
                st, body = grant(
                    "master",
                    {
                        "grant_type": "password",
                        "client_id": "admin-cli",
                        "username": "synthetic-admin",
                        "password": "Synthetic-master-2026!",
                    },
                )
                if st == 200:
                    break
            except (OSError, urllib.error.URLError):
                pass
            if docker("inspect", "--format", "{{.State.Status}}", name) == "exited":
                raise AssertionError(
                    "disposable server exited "
                    + docker(
                        "inspect",
                        "--format",
                        "{{.State.ExitCode}} OOM={{.State.OOMKilled}}",
                        name,
                    )
                )
            time.sleep(1)
        else:
            raise AssertionError("disposable server startup timeout")
        master = body["access_token"]

        def admin(path, body=None, method=None):
            return request("/admin/realms/" + realm + path, body, master, method)

        roles = sorted(
            set(
                sum(CLIENTS.values(), [])
                + [
                    "user",
                    "consultant",
                    "group-chat-consultant",
                    "restricted-agency-admin",
                    "user-admin",
                    "agency-admin",
                    "tenant-admin",
                    "topic-admin",
                ]
            )
        )
        cs = [
            {
                "clientId": c,
                "enabled": True,
                "publicClient": False,
                "serviceAccountsEnabled": True,
                "standardFlowEnabled": False,
                "directAccessGrantsEnabled": False,
                "fullScopeAllowed": False,
                "defaultClientScopes": ["roles"],
                "protocolMappers": [
                    {
                        "name": "command-audience",
                        "protocol": "openid-connect",
                        "protocolMapper": "oidc-audience-mapper",
                        "config": {
                            "included.custom.audience": (
                                "userservice" if c == "backend-consultant-import" else "oriso-task-commands"
                            ),
                            "access.token.claim": "true",
                        },
                    }
                ],
            }
            for c in CLIENTS
        ]
        check(
            "synthetic realm",
            request(
                "/admin/realms",
                {
                    "realm": realm,
                    "enabled": True,
                    "adminEventsEnabled": True,
                    "adminEventsDetailsEnabled": True,
                    "passwordPolicy": "length(12)",
                    "roles": {"realm": [{"name": r} for r in roles]},
                    "clients": cs,
                },
                master,
            )[0],
            201,
        )
        # Expose the deployment's custom identity attributes to the native fixture API.
        profile_config = admin("/users/profile")[1]
        profile_config["unmanagedAttributePolicy"] = "ENABLED"
        check("native unmanaged-attribute fixture policy", admin("/users/profile", profile_config, "PUT")[0], 200)
        verify_native_subject_and_scope(admin, check)
        tokens = {}
        subjects = {}
        secrets = {}
        client_ids = {}
        for c, rs in CLIENTS.items():
            cid = admin("/clients?clientId=" + c)[1][0]["id"]
            client_ids[c] = cid
            subj = admin("/clients/" + cid + "/service-account-user")[1]["id"]
            subjects[c] = subj
            secret = admin("/clients/" + cid + "/client-secret")[1]["value"]
            secrets[c] = secret
            inherited = admin("/users/" + subj + "/role-mappings/realm")[1]
            if inherited:
                check(
                    c + " removes native default grants",
                    admin("/users/" + subj + "/role-mappings/realm", inherited, "DELETE")[0],
                    204,
                )
            reps = [admin("/roles/" + r)[1] for r in rs]
            check(
                c + " direct role grant",
                admin("/users/" + subj + "/role-mappings/realm", reps)[0],
                204,
            )
            check(
                c + " scope grant",
                admin("/clients/" + cid + "/scope-mappings/realm", reps)[0],
                204,
            )
            st, b = grant(
                realm,
                {
                    "grant_type": "client_credentials",
                    "client_id": c,
                    "client_secret": secret,
                },
            )
            check(c + " real token", st, 200)
            tokens[c] = b["access_token"]
        management = seed_legacy(admin, grant, check, realm, client_ids, subjects, secrets, tokens)
        actor = "backend-account-provisioning"
        attempt = str(uuid.uuid4())
        body = {
            "username": "synthetic-asker",
            "email": "asker@example.invalid",
            "firstName": "Synthetic",
            "lastName": "Asker",
            "preferredLanguage": "de",
            "tenantId": "17",
            "password": "Synthetic-user-password-2026!",
            "roles": ["user"],
            "registrationKind": "ASKER",
        }
        path = "/realms/" + realm + "/oriso-commands/v1/account-creations/" + attempt
        st, receipt = authorized(path, body, actor, "PUT", "account.create", attempt, KEY, tenant="17")
        check("creator creates complete account", st, 201)
        account = receipt["accountId"]
        reader = "backend-account-maintenance"
        account_path = "/realms/" + realm + "/oriso-commands/v1/accounts/" + account
        st, projection = authorized(
            account_path, {}, reader, None, "account.read", account, MAINT_KEY, kind="LIFECYCLE", tenant="17"
        )
        check("maintenance bounded projection", st, 200)
        assert projection["username"] == "synthetic-asker" and projection["roles"] == ["user"]
        patch = {"firstName": "Changed", "preferredLanguage": "en"}
        check(
            "maintenance profile uses bounded origin",
            authorized(
                account_path + "/profile",
                patch,
                reader,
                "PATCH",
                "account.profile",
                account,
                MAINT_KEY,
                kind="SELF_SERVICE",
                tenant="17",
            )[0],
            204,
        )
        password = {
            "password": "Replacement-synthetic-password-2026!",
            "passwordTemporary": True,
        }
        check(
            "maintenance password preserves temporary onboarding",
            authorized(
                account_path + "/password",
                password,
                reader,
                "PUT",
                "account.password",
                account,
                MAINT_KEY,
                kind="HUMAN_ADMIN",
                tenant="17",
            )[0],
            204,
        )
        updated_roles = {"roles": ["consultant"]}
        check(
            "maintenance role update is origin limited",
            authorized(
                account_path + "/roles",
                updated_roles,
                reader,
                "PUT",
                "account.roles",
                account,
                MAINT_KEY,
                kind="HUMAN_ADMIN",
                tenant="17",
                roles=["consultant"],
            )[0],
            204,
        )
        combo = dict(
            body,
            username="synthetic-counselling-admin",
            email="admin@example.invalid",
            roles=["consultant", "restricted-agency-admin", "user-admin"],
            registrationKind="CONSULTANT_AGENCY_ADMIN",
        )
        combo_attempt = str(uuid.uuid4())
        check(
            "atomic counselling agency-admin invitation",
            authorized(
                "/realms/" + realm + "/oriso-commands/v1/account-creations/" + combo_attempt,
                combo,
                actor,
                "PUT",
                "account.create",
                combo_attempt,
                KEY,
                kind="INVITATION",
                tenant="17",
                roles=combo["roles"],
            )[0],
            201,
        )
        commands = "/realms/" + realm + "/oriso-commands/v1"
        verify_inventory(admin, check, authorized, commands, MAINT_KEY, subjects)
        verify_projected_account(admin, check, authorized, commands, MAINT_KEY, account, body)
        verify_platform_self_service(admin, grant, check, authorized, commands, MAINT_KEY, realm)
        verify_lifecycle_effects(admin, grant, check, authorized, commands, MAINT_KEY, realm)
        check(
            "lifecycle deactivates bounded target",
            authorized(
                account_path + "/deactivation",
                {},
                reader,
                "POST",
                "account.deactivate",
                account,
                MAINT_KEY,
                kind="LIFECYCLE",
                tenant="17",
            )[0],
            204,
        )
        check(
            "lifecycle deletes bounded account",
            authorized(
                account_path,
                {},
                reader,
                "DELETE",
                "account.delete",
                account,
                MAINT_KEY,
                kind="LIFECYCLE",
                tenant="17",
            )[0],
            204,
        )
        check(
            "repeated lifecycle deletion stays idempotent",
            authorized(
                account_path,
                {},
                reader,
                "DELETE",
                "account.delete",
                account,
                MAINT_KEY,
                kind="LIFECYCLE",
                tenant="17",
            )[0],
            204,
        )
        smtp = {
            "revision": 1,
            "globalSmtpEnabled": True,
            "globalFeatureSystemNotificationEmailsEnabled": True,
            "globalSmtpHost": "smtp.example.invalid",
            "globalSmtpPort": 465,
            "globalSmtpFrom": "synthetic@example.invalid",
            "globalSmtpUsername": " synthetic smtp user ",
            "globalSmtpPassword": " Synthetic opaque password ",
            "globalSmtpSecure": True,
        }
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            first_smtp = list(
                pool.map(
                    lambda _: request(
                        "/realms/" + realm + "/oriso-commands/v1/smtp",
                        smtp,
                        tokens["backend-smtp-sync"],
                        "PUT",
                    )[0],
                    range(2),
                )
            )
        assert sorted(first_smtp) in (
            [200, 200],
            [200, 409],
        ), "first SMTP revision race: " + str(first_smtp)
        check(
            "SMTP task applies bounded snapshot",
            request(
                "/realms/" + realm + "/oriso-commands/v1/smtp",
                smtp,
                tokens["backend-smtp-sync"],
                "PUT",
            )[0],
            200,
        )
        errors = []

        def denied(label, actual, expected=403):
            try:
                check(label, actual, expected)
            except AssertionError as e:
                errors.append(str(e))

        view_role = admin("/clients/" + management + "/roles/view-users")[1]
        check(
            "install synthetic wrong stock grant",
            admin(
                "/users/" + subjects["backend-smtp-sync"] + "/role-mappings/clients/" + management,
                [view_role],
            )[0],
            204,
        )
        denied(
            "new task rejects any actual stock management grant",
            request(
                "/realms/" + realm + "/oriso-commands/v1/smtp",
                smtp,
                tokens["backend-smtp-sync"],
                "PUT",
            )[0],
        )
        check(
            "remove synthetic wrong stock grant",
            admin(
                "/users/" + subjects["backend-smtp-sync"] + "/role-mappings/clients/" + management,
                [view_role],
                "DELETE",
            )[0],
            204,
        )
        otp_path = "/realms/" + realm + "/otp-config/fetch-otp-setup-info/synthetic-counselling-admin"
        check(
            "dedicated OTP task keeps existing setup operation",
            request(otp_path, token=tokens["backend-account-otp"])[0],
            200,
        )
        denied(
            "migration OTP accepts only exact legacy tuple when opted in",
            request(otp_path, token=tokens["backend-admin"])[0],
            200 if legacy_otp else 403,
        )
        otp_actor = "backend-account-otp"
        otp_cid = client_ids[otp_actor]
        human_id = admin("/users?username=synthetic-counselling-admin&exact=true")[1][0]["id"]
        for identity in (otp_actor, "backend-admin"):
            verify_otp_subject_binding(
                admin,
                grant,
                check,
                request,
                realm,
                identity,
                client_ids[identity],
                human_id,
                secrets[identity],
                body["password"],
                otp_path,
                management if identity == "backend-admin" else None,
            )
        denied(
            "creator invalid attempt is a client error",
            authorized(
                "/realms/" + realm + "/oriso-commands/v1/account-creations/not-a-uuid",
                body,
                actor,
                "PUT",
                "account.create",
                "not-a-uuid",
                KEY,
                tenant="17",
            )[0],
            400,
        )
        unusual_attempt = str(uuid.uuid4())
        unusual_body = dict(body, username="synthetic-float-proof", email="float@example.invalid")
        denied(
            "origin numeric timestamp schema rejects floating iat",
            authorized(
                "/realms/" + realm + "/oriso-commands/v1/account-creations/" + unusual_attempt,
                unusual_body,
                actor,
                "PUT",
                "account.create",
                unusual_attempt,
                KEY,
                tenant="17",
                overrides={"iat": time.time(), "exp": int(time.time()) + 50},
            )[0],
        )
        extra_task_role = admin("/roles/account-read")[1]
        check(
            "install unrelated task role",
            admin(
                "/users/" + subjects["backend-smtp-sync"] + "/role-mappings/realm",
                [extra_task_role],
            )[0],
            204,
        )
        denied(
            "new task rejects unrelated task capability",
            request(
                "/realms/" + realm + "/oriso-commands/v1/smtp",
                smtp,
                tokens["backend-smtp-sync"],
                "PUT",
            )[0],
        )
        check(
            "remove unrelated task role",
            admin(
                "/users/" + subjects["backend-smtp-sync"] + "/role-mappings/realm",
                [extra_task_role],
                "DELETE",
            )[0],
            204,
        )
        # Every actor's actual token must be useless at native management routes.
        for task in CLIENTS:
            denied(
                task + " cannot list native users",
                request("/admin/realms/" + realm + "/users", token=tokens[task])[0],
            )
            denied(
                task + " cannot update native realm",
                request(
                    "/admin/realms/" + realm,
                    {"displayName": "forbidden"},
                    tokens[task],
                    "PUT",
                )[0],
            )
        for wrong in (
            "backend-account-maintenance",
            "backend-account-otp",
            "backend-smtp-sync",
        ):
            denied(
                wrong + " cannot provision",
                authorized(path, body, wrong, "PUT", "account.create", attempt, KEY, tenant="17")[0],
            )
        denied(
            "creator cannot maintain",
            request(
                "/realms/" + realm + "/oriso-commands/v1/accounts/" + human_id + "/profile",
                {"firstName": "forbidden"},
                tokens[actor],
                "PATCH",
            )[0],
        )
        denied(
            "creator cannot configure SMTP",
            request(
                "/realms/" + realm + "/oriso-commands/v1/smtp",
                smtp,
                tokens[actor],
                "PUT",
            )[0],
        )

        def creation(data, attempt_id=None, overrides=None, kind="REGISTRATION"):
            attempt_id = attempt_id or str(uuid.uuid4())
            url = "/realms/" + realm + "/oriso-commands/v1/account-creations/" + attempt_id
            origin = proof(
                KEY,
                "account.create",
                attempt_id,
                data,
                actor,
                subjects[actor],
                kind=kind,
                tenant=data.get("tenantId"),
                roles=data["roles"],
                overrides=overrides,
            )
            return attempt_id, url, request(url, data, tokens[actor], "PUT", origin)

        def completion(attempt_id, owned, commit=False, data=None, kind="REGISTRATION", roles=None, tenant="17"):
            data = data or {
                "accountId": owned["accountId"],
                "creationProof": owned["creationProof"],
            }
            operation = "account.commit" if commit else "account.compensate"
            return authorized(
                "/realms/"
                + realm
                + "/oriso-commands/v1/account-creations/"
                + attempt_id
                + ("/commit" if commit else "/compensations"),
                data,
                actor,
                "POST",
                operation,
                attempt_id,
                KEY,
                tenant=tenant,
                kind=kind,
                roles=roles,
            )

        verify_origin_workflows(
            admin, check, authorized, creation, completion, commands, KEY, MAINT_KEY, body, human_id
        )
        denied(
            "create native profile rejects invalid email",
            creation(dict(body, username="synthetic-invalid-email", email="not-an-email"))[2][0],
            400,
        )
        assert not admin("/users?username=synthetic-invalid-email&exact=true")[
            1
        ], "failed native validation must roll back account"
        platform = dict(
            body,
            username="synthetic-platform-escalation",
            email="platform@example.invalid",
            tenantId="0",
            registrationKind="TENANT_ADMIN",
            roles=["user-admin", "agency-admin", "tenant-admin"],
        )
        denied(
            "creator cannot create platform admin",
            creation(platform, kind="HUMAN_ADMIN")[2][0],
        )
        for label, overrides in [
            (
                "expired proof",
                {"iat": int(time.time()) - 120, "exp": int(time.time()) - 60},
            ),
            ("wrong origin target", {"target": str(uuid.uuid4())}),
            ("wrong origin subject", {"taskSubject": str(uuid.uuid4())}),
            ("wrong origin tenant", {"tenantId": "18"}),
            ("wrong origin role", {"roles": ["technical"]}),
        ]:
            denied(
                label,
                creation(
                    dict(
                        body,
                        username="synthetic-" + uuid.uuid4().hex[:8],
                        email=uuid.uuid4().hex + "@example.invalid",
                    ),
                    overrides=overrides,
                )[2][0],
            )
        owned_body = dict(body, username="synthetic-owned", email="owned@example.invalid")
        owned_attempt, owned_path, (st, owned) = creation(owned_body)
        check("owned creation", st, 201)
        replay = creation(owned_body, owned_attempt)[2]
        check("same creation replay", replay[0], 200)
        assert replay[1] == owned
        denied(
            "attempt rejects changed body",
            creation(dict(owned_body, firstName="conflict"), owned_attempt)[2][0],
            409,
        )
        denied(
            "preexisting username cannot become owned",
            creation(owned_body)[2][0],
            409,
        )
        denied(
            "forged compensation proof denied",
            completion(
                owned_attempt,
                owned,
                data={"accountId": owned["accountId"], "creationProof": "forged"},
            )[0],
        )
        denied(
            "compensation cannot delete a different account",
            completion(
                owned_attempt,
                owned,
                data={
                    "accountId": human_id,
                    "creationProof": owned["creationProof"],
                },
            )[0],
        )
        check("creation can commit", completion(owned_attempt, owned, True)[0], 204)
        check(
            "commit tombstone replay",
            completion(owned_attempt, owned, True)[0],
            204,
        )
        denied(
            "committed account cannot be compensated",
            completion(owned_attempt, owned)[0],
            409,
        )
        denied(
            "committed attempt cannot recreate",
            creation(owned_body, owned_attempt)[2][0],
            409,
        )
        assert admin("/users/" + owned["accountId"])[0] == 200
        transient_body = dict(
            body,
            username="synthetic-compensated",
            email="compensated@example.invalid",
        )
        transient_attempt, _, (st, transient) = creation(transient_body)
        check("compensatable creation", st, 201)
        check("owned compensation", completion(transient_attempt, transient)[0], 204)
        check(
            "compensation tombstone replay",
            completion(transient_attempt, transient)[0],
            204,
        )
        denied(
            "compensated account gone",
            admin("/users/" + transient["accountId"])[0],
            404,
        )
        denied(
            "compensated attempt cannot recreate",
            creation(transient_body, transient_attempt)[2][0],
            409,
        )
        denied(
            "compensated creation cannot commit",
            completion(transient_attempt, transient, True)[0],
            409,
        )
        # Receiver verifies issued audience and actual linked service-account tuple.
        mapper = admin("/clients/" + otp_cid + "/protocol-mappers/models")[1][0]
        wrong_mapper = dict(
            mapper,
            config=dict(mapper["config"], **{"included.custom.audience": "wrong-audience"}),
        )
        check(
            "synthetic wrong audience mapper",
            admin(
                "/clients/" + otp_cid + "/protocol-mappers/models/" + mapper["id"],
                wrong_mapper,
                "PUT",
            )[0],
            204,
        )
        st, wrong_aud = grant(
            realm,
            {
                "grant_type": "client_credentials",
                "client_id": otp_actor,
                "client_secret": secrets[otp_actor],
            },
        )
        check("actual wrong audience token", st, 200)
        denied(
            "OTP rejects wrong audience",
            request(otp_path, token=wrong_aud["access_token"])[0],
        )
        check(
            "restore actual task audience",
            admin(
                "/clients/" + otp_cid + "/protocol-mappers/models/" + mapper["id"],
                mapper,
                "PUT",
            )[0],
            204,
        )
        impersonation = admin("/clients/" + management + "/roles/impersonation")[1]
        check(
            "synthetic legacy broad forbidden grant",
            admin(
                "/users/" + subjects["backend-admin"] + "/role-mappings/clients/" + management,
                [impersonation],
            )[0],
            204,
        )
        denied(
            "legacy compatibility rejects actual impersonation grant",
            request(otp_path, token=tokens["backend-admin"])[0],
        )
        check(
            "remove synthetic legacy forbidden grant",
            admin(
                "/users/" + subjects["backend-admin"] + "/role-mappings/clients/" + management,
                [impersonation],
                "DELETE",
            )[0],
            204,
        )
        check(
            "legacy unrelated task grant",
            admin(
                "/users/" + subjects["backend-admin"] + "/role-mappings/realm",
                [extra_task_role],
            )[0],
            204,
        )
        denied(
            "legacy compatibility rejects unrelated task capability",
            request(otp_path, token=tokens["backend-admin"])[0],
        )
        check(
            "remove legacy unrelated task grant",
            admin(
                "/users/" + subjects["backend-admin"] + "/role-mappings/realm",
                [extra_task_role],
                "DELETE",
            )[0],
            204,
        )
        verify_smtp_revisions(admin, check, request, commands + "/smtp", tokens["backend-smtp-sync"], smtp)
        # Concurrent creation and finish serialize; only the winning account may be deleted.
        race_body = dict(body, username="synthetic-race", email="race@example.invalid")
        race_attempt = str(uuid.uuid4())
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            races = list(pool.map(lambda _: creation(race_body, race_attempt)[2], range(2)))
        assert sorted(x[0] for x in races) in (
            [200, 201],
            [201, 409],
        ), "creation race statuses: " + str([x[0] for x in races])
        race_owned = next(x[1] for x in races if x[0] == 201)
        replayed = creation(race_body, race_attempt)[2]
        check("creation race retry returns winner", replayed[0], 200)
        assert replayed[1]["accountId"] == race_owned["accountId"]
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            finishes = list(
                pool.map(
                    lambda commit: completion(race_attempt, race_owned, commit)[0],
                    [True, False],
                )
            )
        assert sorted(finishes) == [204, 409], "commit/compensation race: " + str(finishes)
        # Restart the SAME server data; receipts and terminal tombstones must survive.
        restart_body = dict(body, username="synthetic-restart-open", email="restart@example.invalid")
        restart_attempt, _, (st, restart_owned) = creation(restart_body)
        check("creation before restart", st, 201)
        docker("restart", name)
        base = "http://127.0.0.1:" + docker("port", name, "8080/tcp").split(":")[-1]
        for _ in range(120):
            try:
                st, b = grant(
                    "master",
                    {
                        "grant_type": "password",
                        "client_id": "admin-cli",
                        "username": "synthetic-admin",
                        "password": "Synthetic-master-2026!",
                    },
                )
                if st == 200:
                    master = b["access_token"]
                    break
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(1)
        else:
            raise AssertionError("restart readiness timeout")
        for task in CLIENTS:
            st, b = grant(
                realm,
                {
                    "grant_type": "client_credentials",
                    "client_id": task,
                    "client_secret": secrets[task],
                },
            )
            check(task + " token after restart", st, 200)
            tokens[task] = b["access_token"]
        st, replayed = creation(restart_body, restart_attempt)[2]
        check("open attempt survives restart", st, 200)
        assert replayed == restart_owned
        check(
            "persisted receipt authorizes compensation after restart",
            completion(restart_attempt, restart_owned)[0],
            204,
        )
        denied(
            "committed tombstone survives restart",
            completion(owned_attempt, owned)[0],
            409,
        )
        check(
            "compensated tombstone survives restart",
            completion(transient_attempt, transient)[0],
            204,
        )
        denied(
            "SMTP revision survives restart",
            request(
                "/realms/" + realm + "/oriso-commands/v1/smtp",
                smtp,
                tokens["backend-smtp-sync"],
                "PUT",
            )[0],
            409,
        )
        # Changing the actual linked subject cannot transfer durable creation ownership.
        old_subject = subjects[actor]
        check("synthetic service-account replacement", admin("/users/" + old_subject, method="DELETE")[0], 204)
        replacement = admin("/clients/" + client_ids[actor] + "/service-account-user")[1]["id"]
        assert replacement != old_subject
        defaults = admin("/users/" + replacement + "/role-mappings/realm")[1]
        if defaults:
            check(
                "replacement clears native default roles",
                admin("/users/" + replacement + "/role-mappings/realm", defaults, "DELETE")[0],
                204,
            )
        check(
            "replacement exact task grants",
            admin("/users/" + replacement + "/role-mappings/realm", [admin("/roles/" + r)[1] for r in CLIENTS[actor]])[
                0
            ],
            204,
        )
        subjects[actor] = replacement
        st, new_token = grant(
            realm, {"grant_type": "client_credentials", "client_id": actor, "client_secret": secrets[actor]}
        )
        check("actual replacement owner token", st, 200)
        tokens[actor] = new_token["access_token"]
        denied("new linked owner cannot finish old attempt", completion(owned_attempt, owned, True)[0])
        denied("new linked owner cannot reopen old attempt", creation(owned_body, owned_attempt)[2][0])
        assert admin("/users/" + owned["accountId"])[0] == 200
        smtp_events = [e for e in admin("/admin-events?max=100")[1] if e.get("resourceType") == "ORISO_SMTP_COMMAND"]
        denied("SMTP records sanitized native event", 200 if smtp_events else 404, 200)
        assert all(
            set(json.loads(e.get("representation", "{}"))) == {"revision", "status"} for e in smtp_events
        ), "SMTP audit must contain metadata only"
        if errors:
            raise AssertionError("; ".join(errors))
        print(json.dumps({"checks": checks, "legacyOtpCompatibility": legacy_otp}))
    finally:
        with open("/tmp/oriso-367-disposable-keycloak.log", "w") as log:
            subprocess.run(["docker", "logs", name], stdout=log, stderr=log)
        subprocess.run(
            ["docker", "rm", "-f", name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--image", required=True)
    p.add_argument("--legacy-otp-compatibility", action="store_true")
    a = p.parse_args()
    main(a.image, a.legacy_otp_compatibility)
