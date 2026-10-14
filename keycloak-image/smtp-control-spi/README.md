# SMTP-only receiving boundary — unactivated proposal

This is a bounded alternative for the native capability gap measured in
[Keycloak57](https://github.com/OpenResilienceInitiative/ORISO-Keycloak/issues/57).
It is a review proposal within Keycloak53. Hassan and Shazia still have to accept
the boundary. The production Dockerfile and realm/chart bindings do not install
or enable this module. It contains no account-command API.

The five-actor target remains unchanged. The existing MAIL service account
(`backend-mail`) has exactly `smtp-sync`, `system-email-delivery`,
`notification-dispatch` and `notifications-technical`. It receives no native
management roles. A mail bearer token alone cannot change SMTP configuration.

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
audience, role mappings and effective grants are checked at the receiver. Groups,
composites, inherited defaults and all client-role grants are denied. The fixed
MAIL role union is verified against both current model state and issued token.

## One context key, distinct purposes

The draft uses the sole managed `ORISO_TASK_CONTEXT_KEY` (base64, at least 32
decoded bytes), distinct from the bearer client's secret. UserService also needs
this same key for legitimate cross-service setup/context and hosts ordinary mail
logic. The proof denies a bearer-only caller; it does not isolate code within a
process that holds both the MAIL bearer and the common context key. Such code
can authorize a bounded SMTP command. Even with a valid proof, the receiver
cannot change unrelated realm/user/role fields. This shared-process trust and
key-distribution risk requires Hassan and Shazia's explicit technical acceptance;
the proposal introduces no second key, signer service or broker to hide it.

Proof wire format is `base64url(canonical claims).base64url(signature)` without
padding. Canonical JSON sorts object keys, uses UTF-8 and compact separators.
The receiver verifies all fixed fields and the constant-time signature:

```text
signature = HMAC-SHA256(contextKey, "proof\n" + encodedClaims)
payloadDigest = lowercase-hex(HMAC-SHA256(contextKey, "payload\n" + canonicalBody))
iss=oriso-smtp-sync, aud=oriso-smtp-control, purpose=SMTP_SYNC, actor=MAIL
operation=SMTP_APPLY, method=PUT (or SMTP_STATUS, method=GET, body={})
realm=actual configured realm name; target=actual realm ID
taskClient=backend-mail; taskSubject=configured service-account ID
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
evidence, not an additional runtime permission granted to MAIL.

```sh
mvn -q -f keycloak-image/smtp-control-spi/pom.xml clean package
SMTP_CONTROL_TEST_JAR="$PWD/keycloak-image/smtp-control-spi/target/smtp-control-spi-1.0-SNAPSHOT.jar" \
  python3 -B scripts/test-smtp-control-permissions.py
```

Installing the jar creates one private revision table. Enabling the draft
additionally requires `ORISO_SMTP_CONTROL_ENABLED=true`,
`ORISO_SMTP_CONTROL_REALM`, `IDENTITY_MAIL_SERVICE_SUBJECT` and the context key.
Absent/invalid enabled configuration fails startup. The module is disabled by
default; there is no fallback to native realm administration. The test's H2
database does not establish MariaDB migration or deployed-realm acceptance.
