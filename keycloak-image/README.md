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
role `technical` (the UserService's technical user). The direct-grant flow
`direct-grant-2fa` must be bound as the realm's Direct Grant Flow — both are
included in `charts/keycloak/keycloak-resources/realm.json` for fresh imports;
for existing realms run `scripts/keycloak-apply-2fa-flow.sh`.

### Email branding for each environment

The `oriso` email theme reads `ORISO_PLATFORM_NAME`, `ORISO_ORG_NAME`,
`ORISO_ORG_ADDRESS`, `ORISO_CONTACT_LINE`, `ORISO_PRIMARY_COLOR` and
`ORISO_ACCENT_COLOR` from environment variables, retaining its generated defaults.
Set `ORISO_APP_URL` to the public application origin without a trailing slash.
`ORISO_LOGO_URL` must be an HTTPS image beneath that same origin; other origins
and empty values render a text wordmark without a broken image or empty spacer.
For a stored tenant image use `/service/tenant/public/branding/{actualTenantId}/logo`
under that origin, after verifying anonymous image retrieval.

Set `ORISO_PRIVACY_URL`, `ORISO_IMPRINT_URL`, `ORISO_SETTINGS_URL`,
`ORISO_UNSUBSCRIBE_URL` and `ORISO_LOGIN_URL` for the same deployment too.
The variables are expanded by Keycloak's theme property resolver, not the shell.
The source remains Frontend `src/emails/scripts/buildKeycloakTheme.mts`; regenerate
and sync instead of editing generated FreeMarker files.
