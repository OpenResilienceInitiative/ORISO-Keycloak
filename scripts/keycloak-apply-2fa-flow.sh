#!/bin/bash
# Applies the 2FA direct-grant flow to an EXISTING realm (fresh imports get it
# from realm.json automatically). Reconciles in place, preserving execution IDs.
#
# Run inside (or via kubectl exec into) the Keycloak pod, which must run the
# oriso-keycloak image (stock Keycloak lacks the app-/email-authenticator SPI):
#
#   kubectl -n <ns> exec deploy/keycloak -- bash -s < scripts/keycloak-apply-2fa-flow.sh
#
# Requires admin credentials; export KC_ADMIN_USER / KC_ADMIN_PASSWORD first or
# log kcadm in beforehand. Realm defaults to online-beratung (override: REALM).
#
# To see WHETHER a realm has drifted before changing anything, run the read-only
# check instead — it ships inside the image and names each failing expectation:
#
#   kubectl -n <ns> exec deploy/keycloak -- /opt/keycloak/bin/oriso-verify-2fa-flow.sh
#
# (source: keycloak-image/scripts/keycloak-verify-2fa-flow.sh)
set -euo pipefail

KC=/opt/keycloak/bin/kcadm.sh
REALM="${REALM:-online-beratung}"
FLOW=direct-grant-2fa
# The admin API lives under KC_HTTP_RELATIVE_PATH when one is set (the chart
# sets /auth), so a bare http://localhost:8080 answers 404 and the login fails.
# Override with KC_SERVER when Keycloak answers elsewhere.
KC_SERVER="${KC_SERVER:-http://localhost:8080${KC_HTTP_RELATIVE_PATH:-}}"

if [ -n "${KC_ADMIN_USER:-}" ]; then
  $KC config credentials --server "$KC_SERVER" --realm master \
    --user "$KC_ADMIN_USER" --password "$KC_ADMIN_PASSWORD"
fi

# Refuse an older image before changing its realm. All three providers ship in
# the same installed lifecycle module; a partial password-only flow is not a repair.
PROVIDERS=$($KC get authentication/authenticator-providers -r "$REALM" | tr -d ' \n')
for provider in oriso-claimed-magic-link oriso-magic-link-ordinary-password oriso-claimed-magic-link-attach; do
  if ! echo "$PROVIDERS" | grep -q "\"id\":\"$provider\""; then
    echo "ERROR: required authenticator $provider is not installed; realm unchanged" >&2
    exit 1
  fi
done

# Never delete/recreate a current flow or temporarily bind the stock password
# flow. Keep its Magic Link, OTP and configuration identities through reruns.
FLOWS=$($KC get authentication/flows -r "$REALM" --fields id,alias | tr -d ' \n')
if ! echo "$FLOWS" | grep -q "\"alias\":\"$FLOW\""; then
  $KC create authentication/flows -r "$REALM" \
    -s alias="$FLOW" -s providerId=basic-flow -s topLevel=true -s builtIn=false
fi

execution_rows() {
  $KC get "authentication/flows/$1/executions" -r "$REALM" | tr -d ' \n'
}

# The endpoint flattens descendants. Select only the exact immediate execution,
# so legacy top-level password rows cannot be confused with their replacements.
execution_row() {
  local flow="$1" key="$2" value="$3" row level rows
  rows=$(execution_rows "$flow") || return $?
  rows=$(echo "$rows" | grep -o '{[^{}]*}' || true)
  while read -r row; do
    level=$(echo "$row" | grep -o '"level":[0-9]*' | sed 's/"level"://' || true)
    [ "${level:-0}" = 0 ] || continue
    if echo "$row" | grep -q "\"$key\":\"$value\""; then echo "$row"; fi
  done <<< "$rows"
}

reconcile_execution() {
  local flow="$1" key="$2" value="$3" requirement="$4" priority="$5" row count
  row=$(execution_row "$flow" "$key" "$value")
  if [ -z "$row" ]; then
    if [ "$key" = displayName ]; then
      $KC create "authentication/flows/$flow/executions/flow" -r "$REALM" -s alias="$value" -s type=basic-flow
    else
      $KC create "authentication/flows/$flow/executions/execution" -r "$REALM" -s provider="$value"
    fi
    row=$(execution_row "$flow" "$key" "$value")
  fi
  count=$(echo "$row" | grep -c '"id":')
  if [ "$count" != 1 ]; then
    echo "ERROR: expected one $value execution in $flow; refusing ambiguous repair" >&2
    exit 1
  fi
  row=$(echo "$row" | sed "s/\"requirement\":\"[A-Z]*\"/\"requirement\":\"$requirement\"/")
  if echo "$row" | grep -q '"priority":'; then
    row=$(echo "$row" | sed "s/\"priority\":[0-9]*/\"priority\":$priority/")
  else
    row=$(echo "$row" | sed "s/}$/,\"priority\":$priority}/")
  fi
  echo "$row" > /tmp/2fa-one.json
  $KC update "authentication/flows/$flow/executions" -r "$REALM" -f /tmp/2fa-one.json
}

reconcile_execution "$FLOW" providerId oriso-claimed-magic-link REQUIRED 0
reconcile_execution "$FLOW" displayName oriso-ordinary-password CONDITIONAL 10
reconcile_execution oriso-ordinary-password providerId oriso-magic-link-ordinary-password REQUIRED 0
reconcile_execution oriso-ordinary-password providerId direct-grant-validate-username REQUIRED 10
reconcile_execution oriso-ordinary-password providerId direct-grant-validate-password REQUIRED 20
reconcile_execution "$FLOW" displayName app-otp-conditional CONDITIONAL 30
reconcile_execution app-otp-conditional providerId conditional-user-configured REQUIRED 10
reconcile_execution app-otp-conditional providerId app-authenticator REQUIRED 20
reconcile_execution app-otp-conditional providerId direct-grant-validate-otp REQUIRED 30
reconcile_execution "$FLOW" displayName email-otp-conditional CONDITIONAL 40
reconcile_execution email-otp-conditional providerId conditional-user-configured REQUIRED 10
reconcile_execution email-otp-conditional providerId email-authenticator REQUIRED 20
reconcile_execution "$FLOW" providerId oriso-claimed-magic-link-attach REQUIRED 50

# Only the legacy password executions move. Their required replacements now
# exist inside the conditional password flow. No current Magic Link/OTP row is deleted.
for provider in direct-grant-validate-username direct-grant-validate-password; do
  row=$(execution_row "$FLOW" providerId "$provider")
  if [ -n "$row" ]; then
    if [ "$(echo "$row" | grep -c '"id":')" != 1 ]; then
      echo "ERROR: duplicate legacy password execution; refusing ambiguous repair" >&2; exit 1
    fi
    id=$(echo "$row" | grep -o '"id":"[^"]*"' | sed 's/"id":"\([^\"]*\)"/\1/')
    $KC delete "authentication/executions/$id" -r "$REALM"
  fi
done

# Do not claim successful reconciliation while an unknown extra authentication
# path remains. Every named row above is unique; require the exact direct counts.
require_execution_count() {
  local flow="$1" expected="$2" rows row level count=0
  rows=$(execution_rows "$flow")
  rows=$(echo "$rows" | grep -o '{[^{}]*}' || true)
  while read -r row; do
    [ -n "$row" ] || continue
    level=$(echo "$row" | grep -o '"level":[0-9]*' | sed 's/"level"://' || true)
    if [ "${level:-0}" = 0 ]; then count=$((count + 1)); fi
  done <<< "$rows"
  if [ "$count" != "$expected" ]; then
    echo "ERROR: unexpected executions in $flow; inspect them before retrying" >&2; exit 1
  fi
}
require_execution_count "$FLOW" 5
require_execution_count oriso-ordinary-password 3
require_execution_count app-otp-conditional 3
require_execution_count email-otp-conditional 2

# Existing execution and authenticator configuration identities survive migration.
EXISTING_CONFIG_ID=$(execution_row email-otp-conditional providerId email-authenticator \
  | grep -o '"authenticationConfig":"[^"]*"' \
  | sed 's/"authenticationConfig":"\([^\"]*\)"/\1/' || true)

# Reuse the existing email authenticator configuration; create it only when absent.
# Its identity survives both legacy migration and repeated current-flow repair.
EMAIL_AUTH_ROW=$($KC get "authentication/flows/email-otp-conditional/executions" -r "$REALM" \
  | tr -d ' \n' \
  | grep -o '{[^{}]*"providerId":"email-authenticator"[^{}]*}' || true)
EMAIL_AUTH_ID=$(echo "$EMAIL_AUTH_ROW" | grep -o '"id":"[^"]*"' | head -1 \
  | sed 's/"id":"\([^"]*\)"/\1/' || true)

# A dangling configuration reference can remain from an older failed repair.
# Only reuse a configuration that the realm still has.
if [ -n "$EXISTING_CONFIG_ID" ] \
    && ! $KC get "authentication/config/$EXISTING_CONFIG_ID" -r "$REALM" >/dev/null 2>&1; then
  echo "previous email-otp-config ($EXISTING_CONFIG_ID) is gone; creating a fresh one"
  EXISTING_CONFIG_ID=""
fi

if [ -z "$EMAIL_AUTH_ID" ]; then
  echo "WARN: email-authenticator execution not found; email-otp-config not attached"
elif [ -n "$EXISTING_CONFIG_ID" ]; then
  $KC update "authentication/config/$EXISTING_CONFIG_ID" -r "$REALM" \
    -s alias=email-otp-config \
    -s 'config.length="6"' \
    -s 'config.ttl="900"' \
    -s 'config.senderId="Onlineberatung"' \
    -s 'config.simulation="false"'

  # kcadm cannot patch a single field on an execution row — the endpoint
  # takes a full AuthenticationExecutionInfoRepresentation. Inject the
  # authenticationConfig id into the row we already fetched and PUT it back.
  if echo "$EMAIL_AUTH_ROW" | grep -q '"authenticationConfig"'; then
    UPDATED_ROW=$(echo "$EMAIL_AUTH_ROW" \
      | sed "s/\"authenticationConfig\":\"[^\"]*\"/\"authenticationConfig\":\"$EXISTING_CONFIG_ID\"/")
  else
    UPDATED_ROW=$(echo "$EMAIL_AUTH_ROW" \
      | sed "s/}$/,\"authenticationConfig\":\"$EXISTING_CONFIG_ID\"}/")
  fi
  echo "$UPDATED_ROW" > /tmp/2fa-email-exec.json
  $KC update "authentication/flows/email-otp-conditional/executions" -r "$REALM" \
    -f /tmp/2fa-email-exec.json
  echo "reused existing email-otp-config ($EXISTING_CONFIG_ID) and bound it to execution $EMAIL_AUTH_ID"
else
  # Fresh install: create + attach in a single call. If this fails with
  # "already exists" it means an orphan config with our alias survived from a
  # broken prior run; log clearly instead of silently leaving the execution
  # unconfigured.
  if $KC create "authentication/executions/$EMAIL_AUTH_ID/config" -r "$REALM" \
      -s alias=email-otp-config \
      -s 'config.length="6"' \
      -s 'config.ttl="900"' \
      -s 'config.senderId="Onlineberatung"' \
      -s 'config.simulation="false"'; then
    echo "created email-otp-config and bound it to execution $EMAIL_AUTH_ID"
  else
    echo "ERROR: could not create email-otp-config for execution $EMAIL_AUTH_ID." >&2
    echo "       An orphaned config with this alias likely exists. Delete it via" >&2
    echo "       kcadm delete authentication/config/{id} and rerun this script." >&2
    exit 1
  fi
fi

# Browser flow: the built-in `forms` flow only carries auth-otp-form, which knows
# the app credential alone. For an e-mail-only user its conditional-user-configured
# sees nothing configured, so the whole subflow is skipped and the user reaches the
# app on a password alone. Add the browser-capable e-mail authenticator beside it.
#
# Reconciled on EVERY run rather than skipped when the subflow exists. If a previous
# run created the parent and then failed before its executions, an "already present"
# check would take the skip branch forever and the flow would stay half-built while
# the script reported success.
BROWSER_SUBFLOW=browser-email-otp-conditional

subflow_rows() {
  $KC get "authentication/flows/$BROWSER_SUBFLOW/executions" -r "$REALM" 2>/dev/null \
    | tr -d ' \n'
}

if ! subflow_rows >/dev/null 2>&1 || [ -z "$(subflow_rows)" ]; then
  if $KC create "authentication/flows/forms/executions/flow" -r "$REALM" \
      -s alias="$BROWSER_SUBFLOW" -s type=basic-flow 2>/dev/null; then
    echo "created browser subflow $BROWSER_SUBFLOW"
  else
    echo "WARN: could not create $BROWSER_SUBFLOW; browser logins keep app-only 2FA" >&2
  fi
fi

if [ -n "$(subflow_rows)" ]; then
  # Each child is added only when absent, so a rerun repairs a partial subflow
  # instead of duplicating a complete one.
  for provider in conditional-user-configured email-form-authenticator; do
    if subflow_rows | grep -q "\"providerId\":\"$provider\""; then
      echo "$BROWSER_SUBFLOW already has $provider"
    else
      $KC create "authentication/flows/$BROWSER_SUBFLOW/executions/execution" -r "$REALM" \
        -s provider="$provider" \
        && echo "added $provider to $BROWSER_SUBFLOW"
    fi
  done

  # Requirements are re-applied every run too: a row created but left DISABLED is
  # invisible to a provider-id comparison and does nothing at login time.
  $KC get "authentication/flows/forms/executions" -r "$REALM" > /tmp/2fa-forms-execs.json
  FORMS_ROW=$(tr -d ' \n' < /tmp/2fa-forms-execs.json \
    | grep -o "{[^{}]*\"displayName\":\"$BROWSER_SUBFLOW\"[^{}]*}" || true)
  if [ -n "$FORMS_ROW" ]; then
    echo "$FORMS_ROW" | sed 's/"requirement":"[A-Z]*"/"requirement":"CONDITIONAL"/' \
      > /tmp/2fa-forms-one.json
    $KC update "authentication/flows/forms/executions" -r "$REALM" -f /tmp/2fa-forms-one.json
  else
    echo "WARN: $BROWSER_SUBFLOW is not attached to the forms flow" >&2
  fi

  subflow_rows > /tmp/2fa-sub-execs.json
  for sub_id in $(grep -o '"id":"[^"]*"' /tmp/2fa-sub-execs.json \
      | sed 's/"id":"\([^"]*\)"/\1/'); do
    sub_row=$(grep -o "{[^{}]*\"id\":\"$sub_id\"[^{}]*}" /tmp/2fa-sub-execs.json)
    echo "$sub_row" | sed 's/"requirement":"[A-Z]*"/"requirement":"REQUIRED"/' \
      > /tmp/2fa-sub-one.json
    $KC update "authentication/flows/$BROWSER_SUBFLOW/executions" -r "$REALM" \
      -f /tmp/2fa-sub-one.json
  done
  echo "reconciled $BROWSER_SUBFLOW"
fi

# The otp-config SPI endpoints accept only callers with the realm role
# otp-config-admin, held by the backend Keycloak admin identity (ORISO-Helm#367;
# override the username with SERVICE_ADMIN_USER). The Helm hook
# keycloak-reconcile-service-identities creates that identity; without Helm,
# create the user first, then re-run this script.
SERVICE_ADMIN_USER="${SERVICE_ADMIN_USER:-svc-keycloak-admin}"
if ! $KC get roles/otp-config-admin -r "$REALM" >/dev/null 2>&1; then
  $KC create roles -r "$REALM" -s name=otp-config-admin \
    -s "description=May call the otp-config endpoints of the ORISO Keycloak SPI (backend Keycloak admin identity only)"
fi
if [ -n "$($KC get users -r "$REALM" -q exact=true -q "username=$SERVICE_ADMIN_USER" --fields id --format csv --noquotes)" ]; then
  $KC add-roles -r "$REALM" --uusername "$SERVICE_ADMIN_USER" --rolename otp-config-admin
else
  echo "WARN: user $SERVICE_ADMIN_USER does not exist; 2FA setup through the UserService fails until it" >&2
  echo "      exists with the realm role otp-config-admin (see ORISO-Helm#367)." >&2
fi
$KC update "realms/$REALM" -s "directGrantFlow=$FLOW"

# email OTP needs the `oriso` email theme (ships the otp-email.ftl template the
# SPI mail sender renders) plus realm SMTP settings (set those separately, they
# carry a secret).
$KC update "realms/$REALM" -s "emailTheme=oriso"

echo "2FA flow applied and bound for realm $REALM (emailTheme=oriso)"
