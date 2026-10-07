"""Lost-response recovery and provisional activation at actual native HTTP seam."""

import concurrent.futures
import uuid


def verify_creation_recovery(admin, grant, check, authorized, creation, completion, commands, key, body, realm):
    data = dict(body, username="synthetic-lost-receipt", email="lost-receipt@example.invalid")
    attempt, _, (status, original) = creation(data)
    check("recovery fixture creates provisional account", status, 201)
    assert admin("/users/" + original["accountId"])[1]["enabled"] is False, "OPEN identity must remain disabled"

    def recover(
        attempt_id=attempt,
        kind="ASKER",
        tenant="17",
        roles=None,
        origin_kind="REGISTRATION",
        overrides=None,
        actor="backend-account-provisioning",
    ):
        return authorized(
            commands + "/account-creations/" + attempt_id + "/recovery-claims",
            {"registrationKind": kind},
            actor,
            "POST",
            "account.creation-recover",
            attempt_id,
            key,
            tenant=tenant,
            roles=roles,
            kind=origin_kind,
            overrides=overrides,
        )

    status, recovered = recover()
    check("lost receipt recovery claims exact owned creation", status, 200)
    assert recovered == dict(original, status="RECOVERY_CLAIMED")
    check("recovery replay is idempotent", recover()[0], 200)
    check("recovery fences old commit", completion(attempt, original, True)[0], 409)
    check("recovery fences old create", creation(data, attempt)[2][0], 409)
    for label, kwargs in [
        ("wrong kind", {"kind": "ANONYMOUS", "origin_kind": "ANONYMOUS"}),
        ("wrong tenant", {"tenant": "18"}),
        ("wrong roles", {"roles": ["consultant"], "kind": "CONSULTANT"}),
        ("wrong original origin", {"origin_kind": "INVITATION"}),
        ("foreign subject", {"overrides": {"taskSubject": str(uuid.uuid4())}}),
        ("wrong task", {"actor": "backend-account-maintenance"}),
    ]:
        check("recovery denies " + label, recover(**kwargs)[0], 403)
    check(
        "recovered proof cannot delete foreign account",
        completion(
            attempt, original, data={"accountId": str(uuid.uuid4()), "creationProof": original["creationProof"]}
        )[0],
        403,
    )

    imported_data = dict(
        body,
        username="synthetic-recovery-import",
        email="recovery-import@example.invalid",
        registrationKind="CONSULTANT",
        roles=["consultant", "group-chat-consultant"],
    )
    imported_attempt, _, (status, imported) = creation(imported_data, kind="IMPORT")
    check("import recovery fixture", status, 201)
    check(
        "recovery cannot omit original optional initial role",
        recover(imported_attempt, kind="CONSULTANT", origin_kind="IMPORT", roles=["consultant"])[0],
        403,
    )
    status, imported_claim = recover(
        imported_attempt, kind="CONSULTANT", origin_kind="IMPORT", roles=imported_data["roles"]
    )
    check("exact original import context can recover", status, 200)
    check(
        "recovery compensation cannot omit original role",
        completion(imported_attempt, imported_claim, kind="IMPORT", roles=["consultant"])[0],
        403,
    )
    check(
        "exact recovered import compensates",
        completion(imported_attempt, imported_claim, kind="IMPORT", roles=imported_data["roles"])[0],
        204,
    )
    anonymous_data = dict(
        body,
        username="synthetic-recovery-anonymous",
        email="recovery-anonymous@example.invalid",
        registrationKind="ANONYMOUS",
    )
    anonymous_attempt, _, (status, anonymous) = creation(anonymous_data, kind="ANONYMOUS")
    check("anonymous recovery fixture", status, 201)
    check(
        "recovery exact kind cannot change with same valid origin and roles",
        recover(anonymous_attempt, kind="ASKER", origin_kind="ANONYMOUS")[0],
        403,
    )
    status, anonymous_claim = recover(anonymous_attempt, kind="ANONYMOUS", origin_kind="ANONYMOUS")
    check("anonymous exact recovery", status, 200)
    check(
        "anonymous recovered receipt compensates",
        completion(anonymous_attempt, anonymous_claim, kind="ANONYMOUS")[0],
        204,
    )

    abandoned = str(uuid.uuid4())
    status, tombstone = recover(abandoned)
    check("absent native creation gets durable abandonment fence", status, 200)
    assert tombstone == {"attemptId": abandoned, "accountId": None, "creationProof": None, "status": "ABANDONED"}
    check(
        "abandoned attempt rejects delayed create",
        creation(dict(data, username="synthetic-abandoned", email="abandoned@example.invalid"), abandoned)[2][0],
        409,
    )
    check("abandoned replay remains bounded", recover(abandoned)[0], 200)
    check("abandoned wrong tenant cannot take ownership", recover(abandoned, tenant="18")[0], 403)

    activation_body = dict(body, username="synthetic-provisional-login", email="provisional@example.invalid")
    activation_attempt, _, (status, activation) = creation(activation_body)
    check("activation fixture created", status, 201)

    def login():
        return grant(
            realm,
            {
                "grant_type": "password",
                "client_id": "synthetic-human-login",
                "username": activation_body["username"],
                "password": activation_body["password"],
            },
        )[0]

    check("OPEN account cannot password-login", login(), 400)
    check("first valid commit activates owned identity", completion(activation_attempt, activation, True)[0], 204)
    check("committed account can password-login", login(), 200)
    native = admin("/users/" + activation["accountId"])[1]
    native["enabled"] = False
    check("independent later disable", admin("/users/" + activation["accountId"], native, "PUT")[0], 204)
    check("repeated commit is idempotent", completion(activation_attempt, activation, True)[0], 204)
    check("repeated commit cannot undo later disable", login(), 400)
    status, committed = recover(activation_attempt)
    check("recovery of committed account is diagnostic only", status, 200)
    assert committed["status"] == "COMMITTED"
    check(
        "committed account cannot be compensated after diagnostic", completion(activation_attempt, activation)[0], 409
    )

    # Concurrent recovery of a missing attempt serializes via its unique durable ownership row.
    race = str(uuid.uuid4())
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(pool.map(lambda _: recover(race)[0], range(2)))
    assert sorted(statuses) in ([200, 200], [200, 409]), "concurrent recovery fence: " + str(statuses)
    check("concurrent recovery retry reads fence", recover(race)[0], 200)
    late = str(uuid.uuid4())
    late_data = dict(data, username="synthetic-late-create-race", email="late-race@example.invalid")
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        created = pool.submit(lambda: creation(late_data, late)[2])
        claimed = pool.submit(lambda: recover(late))
        create_status, _ = created.result()
        recovery_status, _ = claimed.result()
    assert create_status in (201, 409) and recovery_status in (200, 409), "late-create/recovery statuses"
    status, fenced = recover(late)
    check("late-create recovery retry establishes definitive fence", status, 200)
    assert fenced["status"] in ("ABANDONED", "RECOVERY_CLAIMED")
    check("late create cannot pass established fence", creation(late_data, late)[2][0], 409)
    if fenced["status"] == "RECOVERY_CLAIMED":
        check("late created owned account compensates", completion(late, fenced)[0], 204)

    class RestartProof:
        def verify_foreign_owner(self):
            check("actual replacement service subject cannot recover prior owner", recover()[0], 403)
            check("actual replacement service subject cannot claim old abandonment", recover(abandoned)[0], 403)

        def verify_after_restart(self):
            status, durable = recover()
            check("recovery claim survives database-preserving restart", status, 200)
            assert durable == recovered
            check("recovery claim still fences old commit after restart", completion(attempt, original, True)[0], 409)
            check("recovered receipt compensates after restart", completion(attempt, durable)[0], 204)
            check("recovered compensation retry is idempotent", completion(attempt, durable)[0], 204)
            check("recovered identity absent", admin("/users/" + original["accountId"])[0], 404)
            check("abandoned fence survives restart", recover(abandoned)[0], 200)
            check(
                "delayed create rejected after restart",
                creation(dict(data, username="synthetic-abandoned", email="abandoned@example.invalid"), abandoned)[2][
                    0
                ],
                409,
            )

    return RestartProof()
