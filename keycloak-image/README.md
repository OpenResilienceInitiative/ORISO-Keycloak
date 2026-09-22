# ORISO Keycloak image (stock + otp-config SPI)

Custom Keycloak image: stock `quay.io/keycloak/keycloak:26.6.3` plus the
onlineBeratung **otp-config SPI**, which provides

- `GET/PUT/POST/DELETE /realms/<realm>/otp-config/**` — the REST endpoints the
  UserService calls for 2FA setup (`fetch-otp-setup-info`, `setup-otp`,
  `delete-otp`, `send-verification-mail`, `setup-otp-mail`),
- the direct-grant authenticators `app-authenticator` (TOTP app, returns the
  `otpType` challenge JSON the frontend expects) and `email-authenticator`
  (login-time email OTP),
- the `MAIL_OTP` credential provider and OTP mail sender (uses the realm's
  SMTP settings and the `otp-email.ftl` theme template already shipped in
  `charts/keycloak/keycloak-resources/custom-theme`).

## Provenance

Vendored from
[Onlineberatung/onlineberatung-keycloak-otp](https://github.com/Onlineberatung/onlineberatung-keycloak-otp)
at commit `fbafb2bab381ffc0c2b31c0d895713fd97e3ef2d` (AGPL, same upstream family
as the ORISO services). Local changes for Keycloak 26.6.3:

1. `pom.xml`: `keycloak.version` 22.0.3 → 26.6.3; added `resteasy-core` (test
   scope) because Keycloak ≥ 24 no longer exposes a JAX-RS `RuntimeDelegate`
   transitively.
2. `AppOtpCredentialService.deleteCredentials`: replaced the removed
   `CredentialHelper.deleteOTPCredential` with
   `SubjectCredentialManager.removeStoredCredentialById`.

All 53 upstream unit tests pass against 26.6.3.

## Build

```sh
docker build -t ghcr.io/openresilienceinitiative/oriso-keycloak:26.6.3-otp keycloak-image/
```

CI builds and pushes on changes under `keycloak-image/**` (see
`.github/workflows/keycloak-image.yml`).

## Realm requirements

The SPI's REST endpoints require a bearer token of a user holding the realm
role `otp-config-admin` as a direct mapping: the backend Keycloak admin
identity `svc-keycloak-admin` (ORISO-Helm#367). The legacy role `technical`
is still accepted until every environment calls with that identity; it is
dropped in the follow-up stage. The direct-grant flow
`direct-grant-2fa` must be bound as the realm's Direct Grant Flow — both are
included in `charts/keycloak/keycloak-resources/realm.json` for fresh imports;
for existing realms run `scripts/keycloak-apply-2fa-flow.sh`.

The technical user additionally needs the realm role `tenant-admin`: the
public tenant-admin onboarding reads the operator DPA and creates the new
tenant server-to-server as that user, and TenantService only serves those
endpoints to `tenant-admin`. `realm.json` grants it on fresh imports; for
existing realms run `scripts/keycloak-grant-technical-tenant-admin.sh`.
