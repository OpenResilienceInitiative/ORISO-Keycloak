#!/bin/bash
# Applies the 2FA direct-grant flow to an EXISTING realm (fresh imports get it
# from realm.json automatically). Idempotent: deletes and recreates the flow.
#
# Run inside (or via kubectl exec into) the Keycloak pod, which must run the
# oriso-keycloak image (stock Keycloak lacks the app-/email-authenticator SPI):
#
#   kubectl -n <ns> exec deploy/keycloak -- bash -s < scripts/keycloak-apply-2fa-flow.sh
#
# Requires admin credentials; export KC_ADMIN_USER / KC_ADMIN_PASSWORD first or
# log kcadm in beforehand. Realm defaults to online-beratung (override: REALM).
set -euo pipefail

KC=/opt/keycloak/bin/kcadm.sh
REALM="${REALM:-online-beratung}"
FLOW=direct-grant-2fa

if [ -n "${KC_ADMIN_USER:-}" ]; then
  $KC config credentials --server http://localhost:8080 --realm master \
    --user "$KC_ADMIN_USER" --password "$KC_ADMIN_PASSWORD"
fi

# rebind to stock flow first so the old custom flow can be deleted
$KC update "realms/$REALM" -s 'directGrantFlow=direct grant'

# Before deleting the flow, capture any existing email-otp-config id from the
# current email-authenticator execution row. Execution rows are FLAT JSON
# (no nested `config:{...}` block), so a simple grep on the row is
# parser-safe — whereas scanning the realm's authenticatorConfig array is
# not, because each entry contains a nested `config` object whose braces
# defeat regex-based object matching.
EXISTING_CONFIG_ID=""
if $KC get "authentication/flows/email-otp-conditional/executions" -r "$REALM" \
    > /tmp/2fa-old-email-execs.json 2>/dev/null; then
  OLD_EMAIL_ROW=$(tr -d ' \n' < /tmp/2fa-old-email-execs.json \
    | grep -o '{[^{}]*"providerId":"email-authenticator"[^{}]*}' || true)
  EXISTING_CONFIG_ID=$(echo "$OLD_EMAIL_ROW" \
    | grep -o '"authenticationConfig":"[^"]*"' \
    | sed 's/"authenticationConfig":"\([^"]*\)"/\1/' || true)
fi

for alias in "$FLOW"; do
  ID=$($KC get authentication/flows -r "$REALM" --fields id,alias 2>/dev/null \
    | tr -d ' \n' | grep -o "{\"id\":\"[^\"]*\",\"alias\":\"$alias\"}" \
    | sed 's/.*"id":"\([^"]*\)".*/\1/' || true)
  if [ -n "$ID" ]; then
    $KC delete "authentication/flows/$ID" -r "$REALM"
    echo "deleted existing flow $alias"
  fi
done

$KC create authentication/flows -r "$REALM" \
  -s alias="$FLOW" -s providerId=basic-flow -s topLevel=true -s builtIn=false
$KC create "authentication/flows/$FLOW/executions/execution" -r "$REALM" -s provider=direct-grant-validate-username
$KC create "authentication/flows/$FLOW/executions/execution" -r "$REALM" -s provider=direct-grant-validate-password
$KC create "authentication/flows/$FLOW/executions/flow" -r "$REALM" -s alias="app-otp-conditional" -s type=basic-flow
$KC create "authentication/flows/app-otp-conditional/executions/execution" -r "$REALM" -s provider=conditional-user-configured
$KC create "authentication/flows/app-otp-conditional/executions/execution" -r "$REALM" -s provider=app-authenticator
$KC create "authentication/flows/app-otp-conditional/executions/execution" -r "$REALM" -s provider=direct-grant-validate-otp
$KC create "authentication/flows/$FLOW/executions/flow" -r "$REALM" -s alias="email-otp-conditional" -s type=basic-flow
$KC create "authentication/flows/email-otp-conditional/executions/execution" -r "$REALM" -s provider=conditional-user-configured
$KC create "authentication/flows/email-otp-conditional/executions/execution" -r "$REALM" -s provider=email-authenticator

# set requirements (subflow rows -> CONDITIONAL, everything else -> REQUIRED)
$KC get "authentication/flows/$FLOW/executions" -r "$REALM" > /tmp/2fa-execs.json
# no python/jq in the keycloak image: rewrite requirement per execution with sed
# on single-object slices produced by kcadm (one GET per execution id).
ids=$(tr -d ' \n' < /tmp/2fa-execs.json | grep -o '"id":"[^"]*"' | sed 's/"id":"\([^"]*\)"/\1/')
for id in $ids; do
  row=$(tr -d ' \n' < /tmp/2fa-execs.json | grep -o "{[^{}]*\"id\":\"$id\"[^{}]*}")
  if echo "$row" | grep -q '"authenticationFlow":true'; then req=CONDITIONAL; else req=REQUIRED; fi
  echo "$row" | sed "s/\"requirement\":\"[A-Z]*\"/\"requirement\":\"$req\"/" > /tmp/2fa-one.json
  $KC update "authentication/flows/$FLOW/executions" -r "$REALM" -f /tmp/2fa-one.json
done

# Attach email-otp-config to the freshly recreated email-authenticator execution
# so the SPI reads length/ttl/senderId/simulation from realm config instead of
# the fallbacks hard-coded in MemoryOtpService.
#
# Truly idempotent: Keycloak does not cascade-delete authenticatorConfig rows
# when the executions that reference them are removed. If EXISTING_CONFIG_ID
# was captured above (pre-delete), we reuse and rebind that row so the config
# id stays stable across reruns. Otherwise we create + attach fresh.

EMAIL_AUTH_ROW=$($KC get "authentication/flows/email-otp-conditional/executions" -r "$REALM" \
  | tr -d ' \n' \
  | grep -o '{[^{}]*"providerId":"email-authenticator"[^{}]*}' || true)
EMAIL_AUTH_ID=$(echo "$EMAIL_AUTH_ROW" | grep -o '"id":"[^"]*"' | head -1 \
  | sed 's/"id":"\([^"]*\)"/\1/' || true)

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

# grant the technical role (SPI endpoints require it) and bind the flow
$KC add-roles -r "$REALM" --uusername technical --rolename technical || true
$KC update "realms/$REALM" -s "directGrantFlow=$FLOW"

# email OTP needs the `oriso` email theme (ships the otp-email.ftl template the
# SPI mail sender renders) plus realm SMTP settings (set those separately, they
# carry a secret).
$KC update "realms/$REALM" -s "emailTheme=oriso"

echo "2FA flow applied and bound for realm $REALM (emailTheme=oriso)"
