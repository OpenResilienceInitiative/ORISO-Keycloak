# Account lifecycle receiving fence

This default-off provider implements the ordinary account creation boundary for
Helm367, selected Scenario C. It uses the existing ACCOUNT_CREATE and ACCOUNT_ADMIN
service accounts and the one shared ORISO_TASK_CONTEXT_KEY. It adds no routine
identity or signing key.

## Receiving contract

`/realms/{realm}/oriso-account-lifecycle/v1/attempts/{attemptId}` supports five
commands: create, owned-read, recover, commit, and compensate. ACCOUNT_CREATE may
use all five. ACCOUNT_ADMIN may recover and compensate only an original creation
attempt. The original owner, checked origin, tenant, target group, payload and
execution fence stay immutable. SETUP, MAIL and RUNTIME cannot use this receiver.

A new account stays disabled in the empty pending group. An immutable attempt and
account are saved in one Keycloak request transaction. Commit joins one exact
reviewed ordinary group and performs first activation. Recovery advances a durable
execution generation or writes an absent-account tombstone. Compensation deletes
only the unchanged, disabled, exact owned pending user. It never searches for or
adopts another account. Local user, child/credential, pending/ordinary group and exact grant/role rows
stay locked while integrity is checked and the transaction completes. Group
privilege writes serialize even when optional native auditing is disabled.

Matching terminal retries return saved receipts without resolving mutable groups
or users. They cannot re-enable an administrator-disabled account or delete a later
account that reuses an old username or ID. Storage uncertainty remains an error;
it never becomes an assumed successful deletion or activation.

Only an initial confirmed duplicate username or email returns a JSON409 body with
one `code`: `USERNAME_NOT_AVAILABLE` or `EMAIL_NOT_AVAILABLE`. Other conflicts keep
the generic error. Responses contain no supplied identifier in an error and use
`Cache-Control: no-store`.

## Configuration and authority

The absent or `false` ORISO_ACCOUNT_LIFECYCLE_ENABLED flag leaves the resource
unregistered. Enabling requires FIVE_ACTORS, an exact realm **name** in
ORISO_ACCOUNT_LIFECYCLE_REALM, distinct configured account actor subjects, a base64
context key containing at least 32 decoded bytes, and reviewed ordinary combined
role mappings in ORISO_ACCOUNT_LIFECYCLE_GROUPS. Existing actors must have their
exact roles, audiences, current service-account bindings and empty technical group.
Native broad or scoped mutation grants invalidate them; a native bypass cannot be
used alongside the receiving fence. Each command also requires a short-lived,
actor/method/realm/attempt/body-bound context proof.

The ordinary kinds are ASKER, ANONYMOUS, CONSULTANT, AGENCY_ADMIN and
CONSULTANT_AGENCY_ADMIN. Protected tenant/platform administrators and service
accounts cannot be created through this ordinary contract. Federated user stores
are unsupported and fail closed for account work. Common-process/common-key trust
is part of Scenario C; it does not create credential isolation between purposes
that share an actor.

## Verification and integration

`mvn -f pom.xml package` runs the module unit tests. With the actual packaged JAR
in LIFECYCLE_C_TEST_JAR, `tests/run_native.py lifecycle --report <path>` runs the full
native HTTP matrix and `tests/run_native.py mariadb --report <path>` runs the full
pinned MariaDB/two-Keycloak matrix. Both require all discovered cases, minimum
case counts, zero skips, stable full source inputs and an unchanged JAR. Sanitized
per-case XML accompanies the JSON report; raw execution logs remain protected.

The default DB fixture is pinned MariaDB11.4. The test-only
LIFECYCLE_C_MARIADB_TEST_IMAGE permits only that digest or the separately verified
MariaDB11.0.6 arm64 digest for a bounded compatibility run. A local pinned test
baseline does not establish the version or compatibility of a deployed image.

Image installation, chart activation, current UserService outbox/domain adapters,
protected onboarding, scoped maintenance/OTP, native grant reconciliation, human
review and deployed browser/mail acceptance must be coordinated. This isolated
receiver does not declare those other parts complete or activate production.
