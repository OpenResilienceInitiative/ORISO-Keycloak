#!/usr/bin/env bash
# Grants the realm role `tenant-admin` to the UserService's technical user on an
# EXISTING realm. Fresh imports get it from realm.json; realms imported before
# this change do not, and then the public tenant-admin onboarding cannot read the
# operator DPA (TenantService answers 403 to the technical user) nor create the
# tenant in the last onboarding step.
#
# Run inside the Keycloak pod (kcadm.sh available, logged in beforehand).
# Realm defaults to online-beratung (override: REALM), user to technical
# (override: TECHNICAL_USER). Idempotent — re-running is harmless.
set -euo pipefail

REALM="${REALM:-online-beratung}"
TECHNICAL_USER="${TECHNICAL_USER:-technical}"
KC=/opt/keycloak/bin/kcadm.sh

$KC add-roles -r "$REALM" --uusername "$TECHNICAL_USER" --rolename tenant-admin
echo "granted realm role tenant-admin to $TECHNICAL_USER in realm $REALM"
$KC get-roles -r "$REALM" --uusername "$TECHNICAL_USER" --fields name
