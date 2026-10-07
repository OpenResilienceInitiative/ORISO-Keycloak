"""Synthetic signing and native setup for the real custom-image HTTP contract tests."""

import base64
import hashlib
import hmac
import json
import time
import uuid


def b64(v):
    return base64.urlsafe_b64encode(v).decode().rstrip("=")


def canonical(v):
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def proof(
    key,
    operation,
    target,
    body,
    client,
    subject,
    kind="REGISTRATION",
    tenant=None,
    roles=None,
    overrides=None,
):
    now = int(time.time())
    claims = {
        "iss": "oriso-userservice",
        "aud": "oriso-task-commands",
        "iat": now,
        "exp": now + 60,
        "jti": str(uuid.uuid4()),
        "purpose": "oriso-command",
        "operation": operation,
        "taskClient": client,
        "taskSubject": subject,
        "originKind": kind,
        "originAction": operation,
        "target": target,
        "tenantId": tenant,
        "roles": roles if roles is not None else ["user"],
        "payloadDigest": b64(
            hmac.new(
                base64.b64decode(key),
                ("payload\n" + canonical(body)).encode(),
                hashlib.sha256,
            ).digest()
        ),
    }
    if overrides:
        claims.update(overrides)
    unsigned = b64(canonical({"alg": "HS256", "typ": "JWT"}).encode()) + "." + b64(canonical(claims).encode())
    return unsigned + "." + b64(hmac.new(base64.b64decode(key), unsigned.encode(), hashlib.sha256).digest())


def verify_native_subject_and_scope(admin, check):
    basic = next(x for x in admin("/client-scopes")[1] if x["name"] == "basic")
    print(
        json.dumps(
            {
                "basic": basic,
                "basicScopeMappings": admin("/client-scopes/" + basic["id"] + "/scope-mappings")[1],
            }
        ),
        flush=True,
    )
    pinned = str(uuid.uuid4())
    pinned_client = "backend-subject-probe"
    check(
        "disabled task client",
        admin(
            "/clients",
            {
                "clientId": pinned_client,
                "enabled": True,
                "publicClient": False,
                "serviceAccountsEnabled": False,
                "standardFlowEnabled": False,
                "directAccessGrantsEnabled": False,
            },
        )[0],
        201,
    )
    pinned_cid = admin("/clients?clientId=" + pinned_client)[1][0]["id"]
    check(
        "linked subject partial import",
        admin(
            "/partialImport",
            {
                "ifResourceExists": "FAIL",
                "users": [
                    {
                        "id": pinned,
                        "username": "service-account-" + pinned_client,
                        "enabled": True,
                        "serviceAccountClientId": pinned_client,
                    }
                ],
            },
        )[0],
        200,
    )
    check(
        "enable pinned service account",
        admin("/clients/" + pinned_cid, {"serviceAccountsEnabled": True}, "PUT")[0],
        204,
    )
    linked = admin("/clients/" + pinned_cid + "/service-account-user")[1]
    assert linked["id"] == pinned, "partial import must preserve linked service user UUID"
    print(
        json.dumps(
            {
                "linkedSubjectPreserved": True,
                "serviceAccountClientIdReturned": linked.get("serviceAccountClientId"),
            }
        ),
        flush=True,
    )


def seed_legacy(admin, grant, check, realm, client_ids, subjects, secrets, tokens):
    legacy = "backend-admin"
    check(
        "synthetic pinned legacy client",
        admin(
            "/clients",
            {
                "clientId": legacy,
                "enabled": True,
                "publicClient": False,
                "serviceAccountsEnabled": True,
                "standardFlowEnabled": False,
                "directAccessGrantsEnabled": False,
                "fullScopeAllowed": False,
                "defaultClientScopes": ["roles"],
                "optionalClientScopes": [],
            },
        )[0],
        201,
    )
    cid = admin("/clients?clientId=" + legacy)[1][0]["id"]
    client_ids[legacy] = cid
    subjects[legacy] = admin("/clients/" + cid + "/service-account-user")[1]["id"]
    secrets[legacy] = admin("/clients/" + cid + "/client-secret")[1]["value"]
    direct = [admin("/roles/otp-config-admin")[1]]
    check(
        "legacy direct OTP baseline",
        admin("/users/" + subjects[legacy] + "/role-mappings/realm", direct)[0],
        204,
    )
    check(
        "legacy OTP scope baseline",
        admin("/clients/" + cid + "/scope-mappings/realm", direct)[0],
        204,
    )
    management = admin("/clients?clientId=realm-management")[1][0]["id"]
    stock = [
        admin("/clients/" + management + "/roles/" + r)[1]
        for r in ("manage-users", "view-users", "query-users", "view-realm")
    ]
    check(
        "legacy direct stock baseline",
        admin(
            "/users/" + subjects[legacy] + "/role-mappings/clients/" + management,
            stock,
        )[0],
        204,
    )
    check(
        "legacy stock scope baseline",
        admin("/clients/" + cid + "/scope-mappings/clients/" + management, stock)[0],
        204,
    )
    st, b = grant(
        realm,
        {
            "grant_type": "client_credentials",
            "client_id": legacy,
            "client_secret": secrets[legacy],
        },
    )
    check("legacy real baseline token", st, 200)
    tokens[legacy] = b["access_token"]
    claims = json.loads(base64.urlsafe_b64decode(tokens[legacy].split(".")[1] + "=="))
    print(
        json.dumps(
            {
                "legacyAudience": claims.get("aud"),
                "legacyRealmRoles": claims.get("realm_access", {}).get("roles", []),
                "legacyManagementRoles": claims.get("resource_access", {}).get("realm-management", {}).get("roles", []),
            }
        ),
        flush=True,
    )
    return management


def verify_projected_account(admin, check, authorized, commands, key, account, body):
    """Native profile state survives the constrained view and partial update."""
    actor = "backend-account-maintenance"
    native = admin("/users/" + account)[1]
    attrs = dict(native["attributes"], unrelated=["keep-this-value"])
    check("seed unrelated native attribute", admin("/users/" + account, dict(native, attributes=attrs), "PUT")[0], 204)
    patch = {"firstName": "Changed", "preferredLanguage": "en"}
    check(
        "partial profile preserves unrelated native attributes",
        authorized(
            commands + "/accounts/" + account + "/profile",
            patch,
            actor,
            "PATCH",
            "account.profile",
            account,
            key,
            kind="SELF_SERVICE",
            tenant="17",
        )[0],
        204,
    )
    updated = admin("/users/" + account)[1]
    assert updated["attributes"]["unrelated"] == ["keep-this-value"]
    assert updated["attributes"]["userId"] == [account] and updated["attributes"]["tenantId"] == ["17"]
    for field in ("username", "email"):
        query = {field: body[field]}
        status, found = authorized(
            commands + "/accounts/search?" + field + "=" + body[field],
            query,
            actor,
            "GET",
            "account.search",
            body[field],
            key,
            kind="LIFECYCLE",
            tenant="17",
        )
        check("bounded " + field + " search", status, 200)
        assert len(found) == 1 and found[0]["id"] == account and "credentials" not in found[0]
    check(
        "cross-tenant read denied",
        authorized(
            commands + "/accounts/" + account,
            {},
            actor,
            "GET",
            "account.read",
            account,
            key,
            kind="LIFECYCLE",
            tenant="18",
        )[0],
        403,
    )

    for address, expected in (("arbitrary@example.invalid", 403), (account + "@beratungcaritas.de", 204)):
        check(
            "lifecycle profile accepts only managed dummy address",
            authorized(
                commands + "/accounts/" + account + "/profile",
                {"email": address},
                actor,
                "PATCH",
                "account.profile",
                account,
                key,
                kind="LIFECYCLE",
                tenant="17",
            )[0],
            expected,
        )


def verify_platform_self_service(admin, grant, check, authorized, commands, key, realm):
    """The signed domain-owner proof preserves only the platform owner's own three actions."""
    name = "synthetic-platform-owner"
    check(
        "native protected platform fixture",
        admin(
            "/users",
            {
                "username": name,
                "firstName": "Synthetic",
                "lastName": "Platform",
                "email": "platform-owner@example.invalid",
                "enabled": True,
                "emailVerified": True,
                "attributes": {"tenantId": ["0"]},
            },
            "POST",
        )[0],
        201,
    )
    account = admin("/users?username=" + name + "&exact=true")[1][0]["id"]
    check(
        "native protected platform role",
        admin("/users/" + account + "/role-mappings/realm", [admin("/roles/tenant-admin")[1]])[0],
        204,
    )
    actor = "backend-account-maintenance"
    path = commands + "/accounts/" + account
    call = lambda suffix, body, method, operation, kind="SELF_SERVICE", target=account: authorized(
        path + suffix, body, actor, method, operation, target, key, kind=kind, tenant="0"
    )
    check("platform self read preserved", call("", {}, "GET", "account.read")[0], 200)
    check(
        "platform self profile preserved",
        call("/profile", {"firstName": "Own profile"}, "PATCH", "account.profile")[0],
        204,
    )
    password = " Native opaque password\n2026! "
    check(
        "platform self password preserved",
        call("/password", {"password": password, "passwordTemporary": False}, "PUT", "account.password")[0],
        204,
    )
    check(
        "native human login fixture",
        admin(
            "/clients",
            {
                "clientId": "synthetic-human-login",
                "publicClient": True,
                "enabled": True,
                "directAccessGrantsEnabled": True,
                "standardFlowEnabled": False,
            },
        )[0],
        201,
    )
    check(
        "native password login preserves opaque characters",
        grant(
            realm,
            {
                "grant_type": "password",
                "client_id": "synthetic-human-login",
                "username": name,
                "firstName": "Synthetic",
                "lastName": "Platform",
                "password": password,
            },
        )[0],
        200,
    )
    check("platform consumed reset read preserved", call("", {}, "GET", "account.read", "PASSWORD_RESET")[0], 200)
    check(
        "platform consumed reset password preserved",
        call(
            "/password",
            {"password": "Reset-authorized-password-2026!", "passwordTemporary": False},
            "PUT",
            "account.password",
            "PASSWORD_RESET",
        )[0],
        204,
    )
    for operation, suffix, data, method in [
        ("account.profile", "/profile", {"firstName": "Forbidden"}, "PATCH"),
        ("account.roles", "/roles", {"roles": ["user"]}, "PUT"),
        ("account.delete", "", {}, "DELETE"),
        ("account.deactivate", "/deactivation", {}, "POST"),
    ]:
        check("PASSWORD_RESET rejects " + operation, call(suffix, data, method, operation, "PASSWORD_RESET")[0], 403)
    check(
        "PASSWORD_RESET wrong target denied",
        call("", {}, "GET", "account.read", "PASSWORD_RESET", str(uuid.uuid4()))[0],
        403,
    )
    check(
        "ONBOARDING cannot recover protected platform account",
        call("", {}, "GET", "account.read", "ONBOARDING")[0],
        403,
    )
    for kind in ("HUMAN_ADMIN", "LIFECYCLE"):
        check(kind + " cannot read protected platform target", call("", {}, "GET", "account.read", kind)[0], 403)
        check(
            kind + " cannot modify protected platform target",
            call("/profile", {"firstName": "Forbidden"}, "PATCH", "account.profile", kind)[0],
            403,
        )
    check(
        "platform self cannot change tenant", call("/profile", {"tenantId": "18"}, "PATCH", "account.profile")[0], 403
    )
    check("platform self cannot change roles", call("/roles", {"roles": ["user"]}, "PUT", "account.roles")[0], 403)
    check("platform self cannot deactivate", call("/deactivation", {}, "POST", "account.deactivate")[0], 403)
    check("platform self cannot delete", call("", {}, "DELETE", "account.delete")[0], 403)
    check(
        "platform self proof cannot substitute target",
        call(
            "/password", {"password": "Forbidden-password-2026!"}, "PUT", "account.password", target=str(uuid.uuid4())
        )[0],
        403,
    )
    assert admin("/users/" + account)[1]["firstName"] == "Own profile"
    # A protected role inherited through a group/composite must protect the same native subject.
    check("platform group fixture", admin("/groups", {"name": "platform-protection"}, "POST")[0], 201)
    group = admin("/groups?search=platform-protection")[1][0]["id"]
    role = admin("/roles/tenant-admin")[1]
    check("platform group grants protected role", admin("/groups/" + group + "/role-mappings/realm", [role])[0], 204)
    check(
        "platform direct role moved to group",
        admin("/users/" + account + "/role-mappings/realm", [role], "DELETE")[0],
        204,
    )
    check("platform native group membership", admin("/users/" + account + "/groups/" + group, method="PUT")[0], 204)
    check(
        "inherited protected human-admin profile denied",
        call("/profile", {"firstName": "Forbidden"}, "PATCH", "account.profile", "HUMAN_ADMIN")[0],
        403,
    )
    check("inherited protected lifecycle delete denied", call("", {}, "DELETE", "account.delete", "LIFECYCLE")[0], 403)
    check(
        "inherited protected self profile preserved",
        call("/profile", {"firstName": "Own profile"}, "PATCH", "account.profile")[0],
        204,
    )


def verify_origin_workflows(admin, check, authorized, creation, completion, commands, key, maint_key, body, target):
    """Import and consumed setup authority stay within their agreed operation sets."""
    imported = dict(
        body,
        username="synthetic-imported",
        email="imported@example.invalid",
        registrationKind="CONSULTANT",
        roles=["consultant"],
    )
    attempt, path, (status, receipt) = creation(imported, kind="IMPORT")
    check("IMPORT consultant creation", status, 201)
    check("IMPORT same creation replay", creation(imported, attempt, kind="IMPORT")[2][0], 200)
    check("IMPORT commit", completion(attempt, receipt, True, kind="IMPORT", roles=imported["roles"])[0], 204)
    check(
        "IMPORT committed tombstone replay",
        completion(attempt, receipt, True, kind="IMPORT", roles=imported["roles"])[0],
        204,
    )
    check(
        "IMPORT cannot compensate committed account",
        completion(attempt, receipt, kind="IMPORT", roles=imported["roles"])[0],
        409,
    )
    check(
        "IMPORT wrong tenant denied",
        completion(attempt, receipt, True, kind="IMPORT", roles=imported["roles"], tenant="18")[0],
        403,
    )
    check(
        "IMPORT cannot create asker",
        creation(dict(body, username="synthetic-import-asker", email="import-asker@example.invalid"), kind="IMPORT")[2][
            0
        ],
        403,
    )
    other_attempt, _, (status, other) = creation(
        dict(body, username="synthetic-non-import", email="non-import@example.invalid")
    )
    check("non-import account creation", status, 201)
    check(
        "IMPORT cannot finish asker attempt",
        completion(other_attempt, other, True, kind="IMPORT", roles=["consultant"])[0],
        403,
    )
    check(
        "IMPORT cannot finish foreign registration kind",
        completion(other_attempt, other, kind="IMPORT", roles=["consultant"])[0],
        403,
    )
    disposable = dict(imported, username="synthetic-import-rollback", email="import-rollback@example.invalid")
    rollback_attempt, _, (status, rollback) = creation(disposable, kind="IMPORT")
    check("IMPORT rollback creation", status, 201)
    check(
        "IMPORT own compensation",
        completion(rollback_attempt, rollback, kind="IMPORT", roles=disposable["roles"])[0],
        204,
    )
    check(
        "IMPORT own compensation tombstone",
        completion(rollback_attempt, rollback, kind="IMPORT", roles=disposable["roles"])[0],
        204,
    )
    check("IMPORT compensated account gone", admin("/users/" + rollback["accountId"])[0], 404)
    provisioner = "backend-account-provisioning"
    maintenance = "backend-account-maintenance"
    account_path = commands + "/accounts/" + receipt["accountId"]
    check(
        "IMPORT cannot read",
        authorized(
            account_path,
            {},
            provisioner,
            "GET",
            "account.read",
            receipt["accountId"],
            key,
            kind="IMPORT",
            tenant="17",
            roles=imported["roles"],
        )[0],
        403,
    )
    check(
        "IMPORT cannot change password",
        authorized(
            account_path + "/password",
            {"password": "Forbidden-import-password-2026!"},
            maintenance,
            "PUT",
            "account.password",
            receipt["accountId"],
            maint_key,
            kind="IMPORT",
            tenant="17",
            roles=imported["roles"],
        )[0],
        403,
    )
    check(
        "receiving importer cannot provision directly",
        authorized(
            path,
            imported,
            "backend-consultant-import",
            "PUT",
            "account.create",
            attempt,
            key,
            kind="IMPORT",
            tenant="17",
            roles=imported["roles"],
        )[0],
        403,
    )
    consultant_id = receipt["accountId"]
    old_admin = admin("/roles/user-admin")[1]
    check(
        "existing consultant unrelated role fixture",
        admin("/users/" + consultant_id + "/role-mappings/realm", [old_admin])[0],
        204,
    )
    status, projection = authorized(
        account_path,
        {},
        maintenance,
        "GET",
        "account.read",
        consultant_id,
        maint_key,
        kind="IMPORT",
        tenant="17",
        roles=[],
    )
    check("IMPORT maintenance reads only existing consultant with the actual empty read grant", status, 200)
    assert set(projection["roles"]) == {"consultant", "user-admin"}
    full_roles = {"roles": ["consultant", "group-chat-consultant", "user-admin"]}
    check(
        "IMPORT empty read grant cannot mutate roles",
        authorized(account_path + "/roles", full_roles, maintenance, "PUT", "account.roles",
                   consultant_id, maint_key, kind="IMPORT", tenant="17", roles=[])[0],
        403,
    )
    check(
        "IMPORT preserves existing unrelated role",
        authorized(
            account_path + "/roles",
            full_roles,
            maintenance,
            "PUT",
            "account.roles",
            consultant_id,
            maint_key,
            kind="IMPORT",
            tenant="17",
            roles=["consultant", "group-chat-consultant"],
        )[0],
        204,
    )
    for desired in (
        ["consultant", "group-chat-consultant"],
        ["consultant", "group-chat-consultant", "user-admin", "agency-admin"],
    ):
        check(
            "IMPORT rejects human admin addition/removal",
            authorized(
                account_path + "/roles",
                {"roles": desired},
                maintenance,
                "PUT",
                "account.roles",
                consultant_id,
                maint_key,
                kind="IMPORT",
                tenant="17",
                roles=["consultant", "group-chat-consultant"],
            )[0],
            403,
        )
    check(
        "IMPORT cannot read an asker",
        authorized(
            commands + "/accounts/" + other["accountId"],
            {},
            maintenance,
            "GET",
            "account.read",
            other["accountId"],
            maint_key,
            kind="IMPORT",
            tenant="17",
            roles=["consultant"],
        )[0],
        403,
    )
    check(
        "IMPORT exact tenant guard",
        authorized(
            account_path,
            {},
            maintenance,
            "GET",
            "account.read",
            consultant_id,
            maint_key,
            kind="IMPORT",
            tenant="18",
            roles=["consultant"],
        )[0],
        403,
    )
    setup_path = commands + "/accounts/" + target
    setup = lambda suffix, data, method, operation, target_id=target: authorized(
        setup_path + suffix, data, maintenance, method, operation, target_id, maint_key, kind="ONBOARDING", tenant="17"
    )
    check("ONBOARDING own persisted account read", setup("", {}, "GET", "account.read")[0], 200)
    check(
        "ONBOARDING bounded password change",
        setup(
            "/password",
            {"password": "Setup-authorized-password-2026!", "passwordTemporary": False},
            "PUT",
            "account.password",
        )[0],
        204,
    )
    check(
        "ONBOARDING cannot change profile",
        setup("/profile", {"firstName": "Forbidden"}, "PATCH", "account.profile")[0],
        403,
    )
    check("ONBOARDING cannot change roles", setup("/roles", {"roles": ["user"]}, "PUT", "account.roles")[0], 403)
    check("ONBOARDING cannot delete", setup("", {}, "DELETE", "account.delete")[0], 403)
    check("ONBOARDING proof cannot substitute target", setup("", {}, "GET", "account.read", str(uuid.uuid4()))[0], 403)
    anonymous = dict(body, username="synthetic-anonymous-full", registrationKind="ANONYMOUS", passwordTemporary=False)
    anonymous.pop("email")
    _, _, (status, created) = creation(anonymous, kind="ANONYMOUS")
    check("anonymous atomic user-role creation", status, 201)
    assert admin("/users/" + created["accountId"])[1]["email"] == created["accountId"] + "@beratungcaritas.de"


def verify_otp_subject_binding(
    admin, grant, check, request, realm, actor, cid, user_id, secret, password, path, management=None
):
    """Even a native token with the right client/audience/roles must name its actual service account."""
    otp_role = admin("/roles/otp-config-admin")[1]
    check(actor + " synthetic human OTP grant", admin("/users/" + user_id + "/role-mappings/realm", [otp_role])[0], 204)
    stock = (
        [
            admin("/clients/" + management + "/roles/" + r)[1]
            for r in ("manage-users", "view-users", "query-users", "view-realm")
        ]
        if management
        else []
    )
    if stock:
        check(
            "legacy human synthetic stock grants",
            admin("/users/" + user_id + "/role-mappings/clients/" + management, stock)[0],
            204,
        )
    check(
        actor + " synthetic password seam", admin("/clients/" + cid, {"directAccessGrantsEnabled": True}, "PUT")[0], 204
    )
    basic = next(scope for scope in admin("/client-scopes")[1] if scope["name"] == "basic")
    existing_scopes = admin("/clients/" + cid + "/default-client-scopes")[1]
    added_basic = not any(scope["id"] == basic["id"] for scope in existing_scopes)
    if added_basic:
        check(
            actor + " native subject mapper seam",
            admin("/clients/" + cid + "/default-client-scopes/" + basic["id"], method="PUT")[0],
            204,
        )
    status, token = grant(
        realm,
        {
            "grant_type": "password",
            "client_id": actor,
            "client_secret": secret,
            "username": "synthetic-counselling-admin",
            "password": password,
        },
    )
    check(actor + " real same-client wrong-subject token", status, 200)
    claims = json.loads(base64.urlsafe_b64decode(token["access_token"].split(".")[1] + "=="))
    assert (
        claims["azp"] == actor
        and claims["sub"] == user_id
        and set(claims["realm_access"]["roles"]) == {"otp-config-admin"}
    )
    audience = claims["aud"]
    assert ("realm-management" if management else "oriso-task-commands") in (
        audience if isinstance(audience, list) else [audience]
    )
    check(
        actor + " restore service-only grants",
        admin("/clients/" + cid, {"directAccessGrantsEnabled": False}, "PUT")[0],
        204,
    )
    check(
        actor + " rejects matching client/audience/role but human subject",
        request(path, token=token["access_token"])[0],
        403,
    )
    if added_basic:
        check(
            actor + " restore baseline scopes",
            admin("/clients/" + cid + "/default-client-scopes/" + basic["id"], method="DELETE")[0],
            204,
        )
    check(
        actor + " remove synthetic human OTP grant",
        admin("/users/" + user_id + "/role-mappings/realm", [otp_role], "DELETE")[0],
        204,
    )
    if stock:
        check(
            "legacy remove synthetic human stock grants",
            admin("/users/" + user_id + "/role-mappings/clients/" + management, stock, "DELETE")[0],
            204,
        )


def verify_smtp_revisions(admin, check, request, path, token, smtp):
    # SMTP preserves opaque credentials and never exposes them in events.
    native_smtp = admin("")[1]["smtpServer"]
    assert (
        native_smtp["user"] == smtp["globalSmtpUsername"] and native_smtp["password"]
    ), "native SMTP representation retains username and masks configured password"
    check(
        "SMTP replay",
        request(
            path,
            smtp,
            token,
            "PUT",
        )[0],
        200,
    )
    check(
        "SMTP conflicting revision",
        request(
            path,
            dict(smtp, globalSmtpHost="other.invalid"),
            token,
            "PUT",
        )[0],
        409,
    )
    disabled = dict(smtp, revision=2, globalSmtpEnabled=False)
    check(
        "SMTP disabled clears snapshot",
        request(
            path,
            disabled,
            token,
            "PUT",
        )[0],
        200,
    )
    assert admin("")[1]["smtpServer"] == {}
    check(
        "SMTP stale revision",
        request(
            path,
            smtp,
            token,
            "PUT",
        )[0],
        409,
    )
    check(
        "SMTP incomplete clears snapshot",
        request(
            path,
            dict(smtp, revision=3, globalSmtpPassword=""),
            token,
            "PUT",
        )[0],
        200,
    )
    assert admin("")[1]["smtpServer"] == {}
