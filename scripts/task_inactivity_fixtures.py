"""Real native HTTP inactivity inventory and access effect contracts."""

import uuid


def verify_inventory(admin, check, authorized, commands, key, subjects):
    """Only locked-rollout lifecycle authority gets a bounded minimal native page."""
    ids = {}
    for name in ("000-inventory-orphan", "001-inventory-pure-tech", "002-inventory-mixed", "003-inventory-platform"):
        check(
            name + " fixture",
            admin(
                "/users",
                {
                    "username": name,
                    "enabled": True,
                    "attributes": {"tenantId": ["0" if name.endswith("platform") else "17"]},
                },
                "POST",
            )[0],
            201,
        )
        ids[name] = admin("/users?username=" + name + "&exact=true")[1][0]["id"]
    check("native composite machine fixture", admin("/roles", {"name": "inventory-machine-alias"}, "POST")[0], 201)
    check(
        "native composite machine authority",
        admin("/roles/inventory-machine-alias/composites", [admin("/roles/account-read")[1]], "POST")[0],
        204,
    )
    check("native machine group fixture", admin("/groups", {"name": "inventory-machine-group"}, "POST")[0], 201)
    group = next(
        g for g in admin("/groups?search=inventory-machine-group")[1] if g["name"] == "inventory-machine-group"
    )["id"]
    check(
        "native inherited machine authority",
        admin("/groups/" + group + "/role-mappings/realm", [admin("/roles/inventory-machine-alias")[1]])[0],
        204,
    )
    for name in ("001-inventory-pure-tech", "002-inventory-mixed"):
        check(
            name + " effective group fixture", admin("/users/" + ids[name] + "/groups/" + group, method="PUT")[0], 204
        )
    client = admin("/clients?clientId=backend-subject-probe")[1][0]["id"]
    check(
        "native client human-role fixture",
        admin("/clients/" + client + "/roles", {"name": "user-admin"}, "POST")[0],
        201,
    )
    check(
        "mixed client human authority",
        admin(
            "/users/" + ids["002-inventory-mixed"] + "/role-mappings/clients/" + client,
            [admin("/clients/" + client + "/roles/user-admin")[1]],
        )[0],
        204,
    )
    check(
        "platform human inventory fixture",
        admin("/users/" + ids["003-inventory-platform"] + "/role-mappings/realm", [admin("/roles/tenant-admin")[1]])[0],
        204,
    )
    cutoff = "2026-01-01T00:00:00Z"
    actor = "backend-account-maintenance"
    path = commands + "/account-inventory"

    def inventory(first=0, max_page=2, kind="LIFECYCLE", tenant=None, roles=None, data=None, target=None):
        data = data or {"cutoff": cutoff, "first": first, "max": max_page}
        target = target or "cutoff:" + data["cutoff"] + "/first:" + str(data["first"]) + "/max:" + str(data["max"])
        return authorized(
            path,
            data,
            actor,
            "POST",
            "account.inventory",
            target,
            key,
            kind=kind,
            tenant=tenant,
            roles=[] if roles is None else roles,
        )

    items = {}
    first = 0
    for _ in range(100):
        status, page = inventory(first)
        check("minimal native inventory page", status, 200)
        assert set(page) == {"accounts", "hasMore"} and len(page["accounts"]) <= 2
        for item in page["accounts"]:
            assert set(item) == {"id", "tenantId", "createdTimestamp", "eligibleHuman"}
            items[item["id"]] = item
        if not page["hasMore"]:
            break
        first += 2
    else:
        raise AssertionError("inventory pagination did not terminate")
    assert items[ids["000-inventory-orphan"]]["eligibleHuman"]
    assert not items[ids["001-inventory-pure-tech"]]["eligibleHuman"]
    assert items[ids["002-inventory-mixed"]]["eligibleHuman"]
    assert items[ids["003-inventory-platform"]]["eligibleHuman"]
    assert all(not items[value]["eligibleHuman"] for value in subjects.values())
    for kind in ("SELF_SERVICE", "HUMAN_ADMIN", "PASSWORD_RESET", "ONBOARDING", "IMPORT"):
        check(kind + " cannot inventory", inventory(kind=kind)[0], 403)
    check("inventory role authority must be empty", inventory(roles=["user"])[0], 403)
    check("inventory cannot claim tenant authority", inventory(tenant="17")[0], 403)
    check("inventory digest binds exact page", inventory(target="cutoff:" + cutoff + "/first:2/max:2")[0], 403)
    for data in (
        {"cutoff": cutoff, "first": 0, "max": 1001},
        {"cutoff": cutoff, "first": -1, "max": 2},
        {"cutoff": "invalid", "first": 0, "max": 2},
        {"cutoff": cutoff, "first": 0, "max": 2, "filter": "all"},
    ):
        check("inventory rejects unbounded or malformed schema", inventory(data=data)[0], 400)


def verify_lifecycle_effects(admin, grant, check, authorized, commands, key, realm):
    """Native sessions, inherited role guards and durable original-enabled effects are preserved."""
    username, password = "synthetic-inactivity", "Synthetic-inactivity-2026!"
    check(
        "native inactivity fixture",
        admin(
            "/users",
            {
                "username": username,
                "firstName": "Synthetic",
                "lastName": "Inactivity",
                "email": "inactivity@example.invalid",
                "enabled": True,
                "emailVerified": True,
                "attributes": {"tenantId": ["17"]},
                "credentials": [{"type": "password", "value": password, "temporary": False}],
            },
            "POST",
        )[0],
        201,
    )
    account = admin("/users?username=" + username + "&exact=true")[1][0]["id"]
    check(
        "native inactivity asker role",
        admin("/users/" + account + "/role-mappings/realm", [admin("/roles/user")[1]])[0],
        204,
    )
    actor = "backend-account-maintenance"
    path = commands + "/accounts/" + account

    def call(suffix, data, method, operation, kind="LIFECYCLE", tenant="17", target=None, roles=None):
        return authorized(
            path + suffix,
            data,
            actor,
            method,
            operation,
            target or account,
            key,
            kind=kind,
            tenant=tenant,
            roles=[] if roles is None else roles,
        )

    status, state = call("/lifecycle-status", {}, "GET", "account.lifecycle-status")
    check("native lifecycle status", status, 200)
    assert set(state) == {"enabled", "sessionCount", "roles"}
    assert state["enabled"] and set(state["roles"]) == {"ASKER"}
    check(
        "native lifecycle actual session",
        grant(
            realm,
            {
                "grant_type": "password",
                "client_id": "synthetic-human-login",
                "username": username,
                "password": password,
            },
        )[0],
        200,
    )
    assert call("/lifecycle-status", {}, "GET", "account.lifecycle-status")[1]["sessionCount"] > 0
    check("native inactivity suspension", call("/suspension", {}, "POST", "account.suspend")[0], 204)
    status, state = call("/lifecycle-status", {}, "GET", "account.lifecycle-status")
    assert status == 200 and state["enabled"] is False and state["sessionCount"] == 0
    check(
        "suspension denies actual login",
        grant(
            realm,
            {
                "grant_type": "password",
                "client_id": "synthetic-human-login",
                "username": username,
                "password": password,
            },
        )[0],
        400,
    )
    check("suspension replay confirmed", call("/suspension", {}, "POST", "account.suspend")[0], 204)
    check(
        "recorded disabled restoration",
        call("/access-restoration", {"enabled": False}, "POST", "account.restore")[0],
        204,
    )
    assert call("/lifecycle-status", {}, "GET", "account.lifecycle-status")[1]["enabled"] is False
    check(
        "recorded enabled restoration",
        call("/access-restoration", {"enabled": True}, "POST", "account.restore")[0],
        204,
    )
    check(
        "restored actual login",
        grant(
            realm,
            {
                "grant_type": "password",
                "client_id": "synthetic-human-login",
                "username": username,
                "password": password,
            },
        )[0],
        200,
    )
    for operation, suffix, data, method in (
        ("account.lifecycle-status", "/lifecycle-status", {}, "GET"),
        ("account.suspend", "/suspension", {}, "POST"),
        ("account.restore", "/access-restoration", {"enabled": True}, "POST"),
    ):
        for kind in ("SELF_SERVICE", "HUMAN_ADMIN", "PASSWORD_RESET", "ONBOARDING", "IMPORT"):
            check(kind + " cannot " + operation, call(suffix, data, method, operation, kind=kind)[0], 403)
        check(operation + " wrong tenant", call(suffix, data, method, operation, tenant="18")[0], 403)
        check(operation + " wrong target", call(suffix, data, method, operation, target=str(uuid.uuid4()))[0], 403)
        check(operation + " role authority forbidden", call(suffix, data, method, operation, roles=["user"])[0], 403)
    for data in ({}, {"enabled": "true"}, {"enabled": True, "roles": ["tenant-admin"]}):
        check("restoration strict schema", call("/access-restoration", data, "POST", "account.restore")[0], 400)
    check("suspension strict schema", call("/suspension", {"enabled": True}, "POST", "account.suspend")[0], 400)
    platform = admin("/users?username=synthetic-platform-owner&exact=true")[1][0]["id"]
    ppath = commands + "/accounts/" + platform
    status, state = authorized(
        ppath + "/lifecycle-status",
        {},
        actor,
        "GET",
        "account.lifecycle-status",
        platform,
        key,
        kind="LIFECYCLE",
        tenant="0",
        roles=[],
    )
    check("protected platform read-only lifecycle status", status, 200)
    assert "OTHER" in state["roles"]
    for suffix, operation, data in (
        ("/suspension", "account.suspend", {}),
        ("/access-restoration", "account.restore", {"enabled": True}),
    ):
        check(
            "protected platform lifecycle mutation denied",
            authorized(
                ppath + suffix, data, actor, "POST", operation, platform, key, kind="LIFECYCLE", tenant="0", roles=[]
            )[0],
            403,
        )
    client = admin("/clients?clientId=backend-account-otp")[1][0]["id"]
    service = admin("/clients/" + client + "/service-account-user")[1]["id"]
    spath = commands + "/accounts/" + service
    status, state = authorized(
        spath + "/lifecycle-status",
        {},
        actor,
        "GET",
        "account.lifecycle-status",
        service,
        key,
        kind="LIFECYCLE",
        tenant=None,
        roles=[],
    )
    check("service lifecycle coarse status", status, 200)
    assert state["roles"] == ["UNKNOWN"]
    check(
        "lifecycle cannot suspend service account",
        authorized(
            spath + "/suspension",
            {},
            actor,
            "POST",
            "account.suspend",
            service,
            key,
            kind="LIFECYCLE",
            tenant=None,
            roles=[],
        )[0],
        403,
    )
    # Native group/client roles must prevent stale asker-only deletion authority.
    group = admin("/groups?search=inventory-machine-group")[1][0]["id"]
    check("inherited role test membership", admin("/users/" + account + "/groups/" + group, method="PUT")[0], 204)
    assert set(call("/lifecycle-status", {}, "GET", "account.lifecycle-status")[1]["roles"]) == {"ASKER", "OTHER"}
    check("inherited role test cleanup", admin("/users/" + account + "/groups/" + group, method="DELETE")[0], 204)
