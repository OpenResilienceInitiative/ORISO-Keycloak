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

# grant the technical role (SPI endpoints require it) and bind the flow
$KC add-roles -r "$REALM" --uusername technical --rolename technical || true
$KC update "realms/$REALM" -s "directGrantFlow=$FLOW"

# email OTP needs the `oriso` email theme (ships the otp-email.ftl template the
# SPI mail sender renders) plus realm SMTP settings (set those separately, they
# carry a secret).
$KC update "realms/$REALM" -s "emailTheme=oriso"

echo "2FA flow applied and bound for realm $REALM (emailTheme=oriso)"
