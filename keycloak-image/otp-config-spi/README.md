# onlineberatung-keycloak-otp

Adds additional endpoints to keycloak to configure 2FA. Currently supports 2FA via:

* App (e.g. Google Authenticator)
* Email

## Installation

* Create a jar (e.g. mvn package)
* Copy `keycloak-otp-config-spi-<VERSION>-keycloak.jar` into the keycloak deployments folder.
  E.g. `/opt/jboss/keycloak/standalone/deployments`, or with 17+ version into `/opt/keycloak/providers`.
* Keycloak will pick up the deployment. If it is deployed successfully, a `.deployed` file will
  appear in the deployments folder with the same name as the jar.
  E.g. `keycloak-otp-config-spi-<VERSION>-keycloak.jar.deployed` (versions below 17). With version 17+ a server build and restart is necessary.
* Configure Authentication flow for direct grant.
* Copy your email theme into themes folder, e.g. `/opt/keycloak/themes/your-theme`. Should contain `otp-email.ftl`.
* Configure email theme for realm.

## Configuration

An authentication flow has to be configured in the Keycloak Admin Console at the Authentication
configuration. We cannot edit the default flows but have to create a copy of an existing flow (e.g.
Direct Grant). Both authenticators in this jar handle Direct Grant flow only. They operate the
following way:

* The current app authenticator just checks if an otp param exists in the request. If it exists, the
  request is forwarded to the default keycloak otp authenticator. The default authenticator handles
  the validation. If no otp param is present, the authenticator sends a request back to frontend
  and the user is prompted to enter their otp.
* The mail authenticator also checks for an otp param, but in addition handles verification if
  it is present.

![Example Auth Flow](docu/flow_config.png)

After flow configuration, we have to bind our custom flow to the Direct Grant flow of Keycloak in
the Bindings tab:

![Example Auth Flow](docu/binding_config.png)

Finally, configure the email theme in your Realm Settings:

![Example Email Theme Config](docu/theme_config.png)

## E-mail code: resend cooldown and cap

A token request without a code mails a new e-mail code, but not without limit
(ORISO-UserService#1338). Both e-mail authenticators (direct grant and browser
form) read three optional keys from the realm's `email-otp-config`; a missing
or invalid key means the default, so no rebuild is needed to change them:

| Key | Default | Meaning |
|---|---|---|
| `resendCooldownSeconds` | `30` | After a mail, no new mail for this long; the last code stays valid. |
| `maxMailsPerWindow` | `5` | At most this many code mails per user in the window. |
| `mailWindowSeconds` | `900` | Length of the sliding window. |

The send history lives in the credential data (`mailsSentAt`), so all pods
share it and a restart forgets nothing. A new code always replaces the old one
and starts with a fresh attempt counter (3 wrong codes kill it); a request
inside the cooldown changes nothing, so it cannot reset that counter.

Direct-grant answers to a request without a code:

- `400` `{"error":"invalid_grant","error_description":"Missing totp","otpType":"EMAIL","resendAvailableInSeconds":30}`
  after a mail went out, or with the remaining seconds inside the cooldown (no mail).
- `429` `{"error":"invalid_grant","error_description":"Too many codes requested","otpType":"EMAIL","resendAvailableInSeconds":745}`
  plus `Retry-After: 745` once the cap is used up (no mail).
- A wrong code still answers `401`; the fourth try on a dead code answers `429`
  with `"Maximal number of failed attempts reached"` (unchanged).


## Scenario C ordinary-target receiver proposal (default off)

This source proposal adds a target check before every OTP setup-information,
credential or email operation. Existing behavior remains active when the task
identity model is absent or blank. Nothing in this change installs SMTP,
activates Scenario C in a chart, or changes the UserService caller.

Explicit `TASK_IDENTITY_MODEL=FIVE_ACTORS` requires canonical
`IDENTITY_ACCOUNT_ADMIN_CLIENT_ID=backend-account-admin` and an explicit UUID
`IDENTITY_ACCOUNT_ADMIN_SERVICE_SUBJECT`; invalid opted-in configuration stops
startup. The signed bearer must match the current realm issuer, exact client,
subject and native service-account ownership; the client must be confidential,
service-account-only and without full scope. Current direct/effective realm roles
must be exactly `account-maintenance`, `account-read`, `otp-config-admin`,
`session-exchange`, with no composites or client roles. The actor must belong only
to the empty `/protected-admins/technical-identities` group beneath an empty root.

The isolated receiving proposal requires audience `oriso-otp` and permits only
`userservice` as an additional audience. This pair is the existing fixture dialect,
not the final production ACCOUNT_ADMIN audience union. Account/session recipient
coordination and production issuance remain open.

Each of the five routes requires actual Keycloak26.6.3 native `canManage(target)`.
The receiver independently denies missing, unclassified, protected-group,
protected platform/Träger role and service-account targets. The reviewed ordinary
centre combination `restricted-agency-admin` plus `user-admin` remains supported.
The actual FGAP2 engine also evaluates the actor's permission inventory: only
ordinary Groups member scopes may be granted. Global, Users, Clients, Roles and
nonordinary Groups powers invalidate access even when no token role reveals them;
unknown permission models fail closed. A view-only target grant cannot expose
setup material. Denied operations change neither credentials nor email state.

**Activation still requires review:** this is a receiving fence, not proof of the
originating human's tenant/workflow authority. Checked-origin/shared-key context,
actual UserService caller selection, human self OTP, protected pre-login invitations
and coordinated chart/full C activation remain open. C mode deliberately rejects
human and legacy backend tokens; default-off mode preserves their existing mediated
flows. Do not enable C mode for those callers until their coordinated acceptance
is complete. No extra runtime identity, key or account-command provider is added.

Local source proof uses the digest-pinned native Keycloak26.6.3 HTTP matrix:

```sh
mvn -B -q -f keycloak-image/otp-config-spi/pom.xml clean package
OTP_C_TEST_JAR="$PWD/keycloak-image/otp-config-spi/target/keycloak-otp-config-spi-1.0-SNAPSHOT-keycloak.jar" \
  python3 keycloak-image/otp-config-spi/tests/test_scenario_c_otp_permissions.py -v
```

The isolated proposal CI workflow separately builds the uninstalled standalone
SMTP JAR and runs its unchanged 19-case HTTP script; OTP has a 24-case floor covering
all five routes, native privileges, signed-token denial and legacy protected-human
protocols. Missing fixtures/JARs, reduced case counts, errors and skips fail the job.
Only nonsecret counts and source/JAR hashes are uploaded. Production image
packaging and deployed acceptance remain separate.
