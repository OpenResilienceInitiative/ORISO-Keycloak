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
# It checks REQUIREMENTS and HIERARCHY, not just which providers are present.
# A flow whose executions are all DISABLED, or a subflow that exists but hangs
# off nothing the realm actually uses, looks identical to a correct one if you
# only compare provider ids — and would let exactly the drift this script is
# for pass as healthy.
#
# Run inside (or via kubectl exec into) the Keycloak pod:
#
#   kubectl -n <ns> exec deploy/keycloak -- bash -s < scripts/keycloak-verify-2fa-flow.sh
#
# Export KC_ADMIN_USER / KC_ADMIN_PASSWORD first, or log kcadm in beforehand.
# Realm defaults to online-beratung (override: REALM).
#
# Exit codes: 0 = realm matches the contract, 1 = drift (each failing check is
# named), 2 = could not talk to Keycloak, or a query failed so the answer is
# unknown. Unknown is never reported as drift: "we could not look" and "it is
# broken" call for different actions.
set -uo pipefail

KC=/opt/keycloak/bin/kcadm.sh
REALM="${REALM:-online-beratung}"
FLOW=direct-grant-2fa
BROWSER_SUBFLOW=browser-email-otp-conditional

FAILURES=0

pass() { printf '  OK    %s\n' "$1"; }
fail() { printf '  DRIFT %s\n' "$1"; FAILURES=$((FAILURES + 1)); }
unknown() { printf '  ERROR %s\n' "$1" >&2; exit 2; }

if [ -n "${KC_ADMIN_USER:-}" ]; then
  if ! $KC config credentials --server http://localhost:8080 --realm master \
      --user "$KC_ADMIN_USER" --password "$KC_ADMIN_PASSWORD" >/dev/null 2>&1; then
    unknown "could not authenticate against Keycloak"
  fi
fi

REALM_JSON=$($KC get "realms/$REALM" 2>/dev/null | tr -d ' \n')
if [ -z "$REALM_JSON" ]; then
  unknown "could not read realm $REALM"
fi

field() {
  echo "$REALM_JSON" | grep -o "\"$1\":\"[^\"]*\"" | head -1 \
    | sed "s/\"$1\":\"\([^\"]*\)\"/\1/"
}

# Raw execution rows of a flow. Fails (non-zero) when the query itself failed,
# which the callers turn into exit 2 rather than into a drift report.
executions_of() {
  $KC get "authentication/flows/$1/executions" -r "$REALM" 2>/dev/null | tr -d ' \n'
}

# "provider:REQUIREMENT" per execution, in order. Subflow rows carry a
# displayName instead of a providerId, so they appear under their alias.
#
# Only the rows of the flow itself: the executions endpoint returns the whole
# tree, so a conditional subflow's children arrive inline right after it, at
# level 1. Comparing that flattened list against the expected top-level entries
# reports every correctly nested realm as drifted — the children are checked on
# their own subflow below.
entries_of() {
  local rows="$1"
  echo "$rows" \
    | grep -o '{[^{}]*}' \
    | while read -r row; do
        level=$(echo "$row" | grep -o '"level":[0-9]*' \
          | sed 's/"level"://')
        [ "${level:-0}" = "0" ] || continue
        name=$(echo "$row" | grep -o '"providerId":"[^"]*"' \
          | sed 's/"providerId":"\([^"]*\)"/\1/')
        if [ -z "$name" ]; then
          name=$(echo "$row" | grep -o '"displayName":"[^"]*"' \
            | sed 's/"displayName":"\([^"]*\)"/\1/')
        fi
        req=$(echo "$row" | grep -o '"requirement":"[^"]*"' \
          | sed 's/"requirement":"\([^"]*\)"/\1/')
        [ -n "$name" ] && printf '%s:%s ' "$name" "$req"
      done \
    | sed 's/ $//'
}

expect_entries() {
  local flow="$1" expected="$2" rows actual
  rows=$(executions_of "$flow") || unknown "could not read executions of $flow"
  if [ -z "$rows" ]; then
    fail "$flow: flow missing entirely (expected: $expected)"
    return
  fi
  actual=$(entries_of "$rows")
  if [ "$actual" = "$expected" ]; then
    pass "$flow: $expected"
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

if [ -n "$BROWSER_FLOW" ]; then
  pass "browserFlow = $BROWSER_FLOW"
else
  fail "browserFlow is unset — no browser login has a second factor at all"
fi
echo

echo "Direct grant (app and admin login)"
expect_entries "$FLOW" \
  "direct-grant-validate-username:REQUIRED direct-grant-validate-password:REQUIRED app-otp-conditional:CONDITIONAL email-otp-conditional:CONDITIONAL"
expect_entries "app-otp-conditional" \
  "conditional-user-configured:REQUIRED app-authenticator:REQUIRED direct-grant-validate-otp:REQUIRED"
expect_entries "email-otp-conditional" \
  "conditional-user-configured:REQUIRED email-authenticator:REQUIRED"

EMAIL_ROWS=$(executions_of "email-otp-conditional") \
  || unknown "could not read executions of email-otp-conditional"
EMAIL_ROW=$(echo "$EMAIL_ROWS" | grep -o '{[^{}]*"providerId":"email-authenticator"[^{}]*}')
if echo "$EMAIL_ROW" | grep -q '"authenticationConfig"'; then
  pass "email-authenticator carries an authenticatorConfig"
else
  fail "email-authenticator has no authenticatorConfig — length, ttl and senderId fall back to the values compiled into MemoryOtpService, and simulation may stay on, which prints codes to the log instead of mailing them"
fi
echo

echo "Browser flow (Matrix and Element SSO, account console)"
# Walk the flow the realm actually uses. A correct subflow attached to a flow
# nothing is bound to protects nobody.
BOUND_ROWS=$(executions_of "$BROWSER_FLOW") \
  || unknown "could not read executions of the bound browser flow $BROWSER_FLOW"
if echo "$BOUND_ROWS" | grep -q '"displayName":"forms"'; then
  pass "$BROWSER_FLOW contains the forms subflow"

  FORMS_ROWS=$(executions_of "forms") || unknown "could not read executions of forms"
  FORMS_ENTRIES=$(entries_of "$FORMS_ROWS")

  case " $FORMS_ENTRIES " in
    *" auth-username-password-form:REQUIRED "*)
      pass "forms: username/password form is REQUIRED" ;;
    *)
      fail "forms: expected auth-username-password-form:REQUIRED, found [$FORMS_ENTRIES]" ;;
  esac

  case " $FORMS_ENTRIES " in
    *" $BROWSER_SUBFLOW:CONDITIONAL "*)
      pass "forms: $BROWSER_SUBFLOW is attached and CONDITIONAL"
      expect_entries "$BROWSER_SUBFLOW" \
        "conditional-user-configured:REQUIRED email-form-authenticator:REQUIRED"
      ;;
    *" $BROWSER_SUBFLOW:"*)
      fail "forms: $BROWSER_SUBFLOW is attached but not CONDITIONAL — found [$FORMS_ENTRIES]" ;;
    *)
      fail "forms: $BROWSER_SUBFLOW is not attached — a counsellor whose second factor is e-mail is asked for no second factor at all on any browser login, because the built-in auth-otp-form only knows the app credential" ;;
  esac
else
  fail "$BROWSER_FLOW does not contain a forms subflow — this realm's browser login does not look like a stock Keycloak one; check it by hand"
fi
echo

if [ "$FAILURES" -eq 0 ]; then
  echo "Realm $REALM matches the 2FA contract."
  exit 0
fi

echo "$FAILURES check(s) drifted from the contract." >&2
echo "Reconcile with: kubectl -n <ns> exec deploy/keycloak -- bash -s < scripts/keycloak-apply-2fa-flow.sh" >&2
exit 1
