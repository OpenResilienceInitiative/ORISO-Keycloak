#!/bin/bash
# Reports whether a LIVE realm still carries the ORISO 2FA contract, and exits
# non-zero when it does not. Read-only: it never writes to the realm.
#
# It exists because `--import-realm` only seeds a realm that does not yet exist
# (see charts/keycloak/templates/keycloak-deployment.yaml in ORISO-Helm). Every
# environment whose realm predates a change to realm.json therefore keeps its
# old flows, and nothing says so. That is how Staging sat on the stock
# `direct grant` flow for a week while Dev was correct — ORISO-Frontend#1402.
#
# Run inside (or via kubectl exec into) the Keycloak pod:
#
#   kubectl -n <ns> exec deploy/keycloak -- bash -s < scripts/keycloak-verify-2fa-flow.sh
#
# Export KC_ADMIN_USER / KC_ADMIN_PASSWORD first, or log kcadm in beforehand.
# Realm defaults to online-beratung (override: REALM).
#
# Exit codes: 0 = realm matches the contract, 1 = drift (each failing check is
# named), 2 = could not talk to Keycloak at all.
set -uo pipefail

KC=/opt/keycloak/bin/kcadm.sh
REALM="${REALM:-online-beratung}"
FLOW=direct-grant-2fa

FAILURES=0

pass() { printf '  OK    %s\n' "$1"; }
fail() { printf '  DRIFT %s\n' "$1"; FAILURES=$((FAILURES + 1)); }

if [ -n "${KC_ADMIN_USER:-}" ]; then
  if ! $KC config credentials --server http://localhost:8080 --realm master \
      --user "$KC_ADMIN_USER" --password "$KC_ADMIN_PASSWORD" >/dev/null 2>&1; then
    echo "ERROR: could not authenticate against Keycloak" >&2
    exit 2
  fi
fi

REALM_JSON=$($KC get "realms/$REALM" 2>/dev/null | tr -d ' \n')
if [ -z "$REALM_JSON" ]; then
  echo "ERROR: could not read realm $REALM" >&2
  exit 2
fi

field() { echo "$REALM_JSON" | grep -o "\"$1\":\"[^\"]*\"" | head -1 | sed "s/\"$1\":\"\([^\"]*\)\"/\1/"; }

# Lists the providerIds of a flow's executions, in order, space separated.
providers_of() {
  $KC get "authentication/flows/$1/executions" -r "$REALM" 2>/dev/null \
    | tr -d ' \n' \
    | grep -o '"providerId":"[^"]*"' \
    | sed 's/"providerId":"\([^"]*\)"/\1/' \
    | tr '\n' ' ' \
    | sed 's/ $//'
}

expect_providers() {
  local flow="$1" expected="$2" actual
  actual=$(providers_of "$flow")
  if [ "$actual" = "$expected" ]; then
    pass "$flow: $expected"
  elif [ -z "$actual" ]; then
    fail "$flow: flow missing entirely (expected: $expected)"
  else
    fail "$flow: expected [$expected] but found [$actual]"
  fi
}

echo "Realm $REALM — ORISO 2FA contract"
echo

echo "Bindings"
DIRECT_GRANT_FLOW=$(field directGrantFlow)
BROWSER_FLOW=$(field browserFlow)
EMAIL_THEME=$(field emailTheme)

if [ "$DIRECT_GRANT_FLOW" = "$FLOW" ]; then
  pass "directGrantFlow = $FLOW"
else
  fail "directGrantFlow = '${DIRECT_GRANT_FLOW:-<unset>}' (expected $FLOW) — app and admin logins get no otpType challenge, so the code field never appears"
fi

if [ "$EMAIL_THEME" = "oriso" ]; then
  pass "emailTheme = oriso"
else
  fail "emailTheme = '${EMAIL_THEME:-<unset>}' (expected oriso) — the OTP mail template is missing, so e-mail codes cannot be sent"
fi

printf '  INFO  browserFlow = %s\n' "${BROWSER_FLOW:-<unset>}"
echo

echo "Direct grant (app and admin login)"
expect_providers "$FLOW" \
  "direct-grant-validate-username direct-grant-validate-password"
expect_providers "app-otp-conditional" \
  "conditional-user-configured app-authenticator direct-grant-validate-otp"
expect_providers "email-otp-conditional" \
  "conditional-user-configured email-authenticator"

EMAIL_ROW=$($KC get "authentication/flows/email-otp-conditional/executions" -r "$REALM" 2>/dev/null \
  | tr -d ' \n' \
  | grep -o '{[^{}]*"providerId":"email-authenticator"[^{}]*}')
if echo "$EMAIL_ROW" | grep -q '"authenticationConfig"'; then
  pass "email-authenticator carries an authenticatorConfig"
else
  fail "email-authenticator has no authenticatorConfig — length, ttl and senderId fall back to the values compiled into MemoryOtpService, and simulation may stay on, which prints codes to the log instead of mailing them"
fi
echo

echo "Browser flow (Matrix and Element SSO, account console)"
BROWSER_FORMS=$(providers_of "forms")
if echo "$BROWSER_FORMS" | grep -q 'auth-username-password-form'; then
  pass "forms: carries the username/password form"
else
  fail "forms: expected a username/password form but found [${BROWSER_FORMS:-<empty>}]"
fi

BROWSER_EMAIL=$(providers_of "browser-email-otp-conditional")
if [ -n "$BROWSER_EMAIL" ]; then
  expect_providers "browser-email-otp-conditional" \
    "conditional-user-configured email-form-authenticator"
else
  fail "browser-email-otp-conditional: missing — a counsellor whose second factor is e-mail is asked for no second factor at all on any browser login, because the built-in auth-otp-form only knows the app credential"
fi
echo

if [ "$FAILURES" -eq 0 ]; then
  echo "Realm $REALM matches the 2FA contract."
  exit 0
fi

echo "$FAILURES check(s) drifted from the contract." >&2
echo "Reconcile with: kubectl -n <ns> exec deploy/keycloak -- bash -s < scripts/keycloak-apply-2fa-flow.sh" >&2
exit 1
