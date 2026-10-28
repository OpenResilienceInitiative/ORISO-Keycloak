# SMTP configuration receiving boundary

This is a bounded alternative for the native capability gap measured in
[Keycloak57](https://github.com/OpenResilienceInitiative/ORISO-Keycloak/issues/57).
It is a review proposal within Keycloak53. Hassan and Shazia still have to accept
the boundary. The production Dockerfile installs the lifecycle, OTP and SMTP modules.
Explicit coordinated chart configuration enables them; defaults remain disabled. It contains no account-command API.

The five-actor model and sole context key remain unchanged. SMTP_SYNC belongs to
SETUP (`backend-setup`), whose exact roles are config-wizard,
invitation-reservations, consultant-import and smtp-sync. Its exact audiences are
tenantservice, agencyservice, consultingtypeservice, userservice and
oriso-task-commands. MAIL retains system-email-delivery, notification-dispatch and
notifications-technical, with only the four service audiences. MAIL cannot configure
SMTP even with a valid common-key MAC. Neither actor receives native management roles.

## Public HTTP contract

`PUT /realms/{realm}/oriso-smtp-control/v1/smtp` accepts only the existing global
SMTP snapshot fields and its nonnegative revision. Mixed realm settings and
unknown fields are rejected. A valid disabled/incomplete snapshot clears SMTP;
invalid input never changes either the configuration or revision. The response
contains only revision and status. A same-revision/same-payload retry is harmless;
a lower revision or same-revision/different-payload command returns 409.

`GET` at the same URL returns revision/status only. It does not return SMTP
credentials. There is no forwarding or proxy to the stock Admin REST API.

Both operations require a real Keycloak bearer token and an
`X-ORISO-Task-Context` proof. Direct service-account subject, client, issuer,
audience, role mappings and effective grants are checked at the receiver. SETUP
must belong only to `/protected-admins/technical-identities`, matching the
standalone Helm preparation. The leaf and its top-level parent must have no
role mappings, including duplicate SETUP roles. Missing, arbitrary, additional or
lookalike nested memberships are denied. Composites, inherited defaults and all
client-role grants remain denied. The fixed SETUP role union is verified against
both current model state and issued token. There is no groupless legacy fallback.

The draft additionally requires the pinned Keycloak26.6.3 FGAP v2 schema. It
evaluates the complete current native permission inventory with Keycloak's own
authorization engine: global and target-scoped Users, Clients, Groups and Roles,
including their native scopes. Target types come from native scope-permission
metadata; a target resource's type field alone is insufficient. Unsupported,
missing or incomplete native inventory fails closed. The same native identity,
evaluation context and typed permission path is used as `MgmtPermissions`; this
does not implement a separate policy solver or enumerate human accounts.

Rejecting SMTP when native powers exist does **not** revoke those powers. A
privileged installer can still grant SETUP a native capability used through stock
Admin APIs. Production policy inventory and real native API denials remain
separate activation gates. The receiving check proves only that this SMTP
resource refuses a currently privileged actor.

## One context key, separate credentials

The receiver uses the sole ORISO_TASK_CONTEXT_KEY (base64, at least32 decoded
bytes), distinct from the SETUP client secret. SETUP authorizes SMTP configuration;
MAIL authorizes delivery. A MAIL bearer plus a valid common-key MAC is refused.
UserService currently holds all five actor credentials and this key. This is a
credential-level boundary, not isolation against a fully compromised colocated
UserService process that can obtain SETUP. No additional actor, signer or key is
introduced. The receiver cannot change unrelated realm, user or role settings.

Proof wire format is `base64url(canonical claims).base64url(signature)` without
padding. Canonical JSON sorts object keys, uses UTF-8 and compact separators.
The receiver verifies all fixed fields and the constant-time signature:

```text
signature = HMAC-SHA256(contextKey, "proof\n" + encodedClaims)
payloadDigest = lowercase-hex(HMAC-SHA256(contextKey, "payload\n" + canonicalBody))
iss=oriso-smtp-sync, aud=oriso-smtp-control, purpose=SMTP_SYNC, actor=SETUP
operation=SMTP_APPLY, method=PUT (or SMTP_STATUS, method=GET, body={})
realm=actual configured realm name; target=actual realm ID
taskClient=backend-setup; taskSubject=configured service-account ID
jti=canonical UUID; nonce=32 lowercase hex characters
iat <= now + 5; now - 60 <= iat; now < exp <= iat + 60
```

The revision is the replay/idempotency boundary for updates. JTI/nonce identify
one short-lived command; they do not add another signing key or actor. Replays
after TTL are denied. A valid retry during TTL cannot reset a newer revision or
change the payload at an already-used revision.

## Local proof only

The test seam is the real receiving HTTP resource and public native Admin APIs,
using real service-account tokens in an isolated digest-pinned Keycloak26.6.3.
The standalone jar is mounted into that throwaway server only. Credentials are
synthetic; the test removes its container. Native Admin readback is installer
evidence, not an additional runtime permission granted to SETUP.

```sh
mvn -q -f keycloak-image/smtp-control-spi/pom.xml clean package
SMTP_CONTROL_TEST_JAR="$PWD/keycloak-image/smtp-control-spi/target/smtp-control-spi-1.0-SNAPSHOT.jar" \
  python3 -B scripts/test-smtp-control-permissions.py
```

Installing the jar creates one private revision table. Enabling the draft
additionally requires `ORISO_SMTP_CONTROL_ENABLED=true`,
`ORISO_SMTP_CONTROL_REALM`, `IDENTITY_SETUP_SERVICE_SUBJECT` and the context key.
Absent/invalid enabled configuration fails startup. The module is disabled by
default; there is no fallback to native realm administration. The test's H2
database does not establish MariaDB migration or deployed-realm acceptance.
