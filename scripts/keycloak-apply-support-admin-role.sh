#!/bin/bash
# Creates the ADR-018 `global-support-admin` realm role on an EXISTING realm.
#
# realm.json is imported on FIRST START ONLY, so a realm that is already running
# never picks the role up. Without it, creating a Global Support Admin fails at
# role assignment: UserService rolls the Keycloak user back and the account is
# left in PROVISIONING_FAILED. Run this once per already-running environment
# before enabling `supportAccess.enabled` in the Helm values.
#
# Run inside (or via kubectl exec into) the Keycloak pod:
#
#   kubectl -n <ns> exec deploy/keycloak -- bash -s < scripts/keycloak-apply-support-admin-role.sh
#
# Requires admin credentials; export KC_ADMIN_USER / KC_ADMIN_PASSWORD first or
# log kcadm in beforehand. Realm defaults to online-beratung (override: REALM).
#
# Idempotent: an existing role is left untouched.
set -euo pipefail

KC=/opt/keycloak/bin/kcadm.sh
REALM="${REALM:-online-beratung}"
ROLE=global-support-admin
DESCRIPTION="Global Support Admin (ADR-018): the only role of a support identity. Grants no tenant, agency, consultant or user-admin privileges; usable solely for the live support handshake."

if [ -n "${KC_ADMIN_USER:-}" ]; then
  $KC config credentials --server http://localhost:8080 --realm master \
    --user "$KC_ADMIN_USER" --password "$KC_ADMIN_PASSWORD"
fi

if $KC get "roles/$ROLE" -r "$REALM" >/dev/null 2>&1; then
  echo "Realm role '$ROLE' already exists in realm '$REALM' — nothing to do."
else
  $KC create roles -r "$REALM" -s "name=$ROLE" -s "description=$DESCRIPTION"
  echo "Created realm role '$ROLE' in realm '$REALM'."
fi

# Verify rather than trust the exit code: this role is the whole authorization
# basis of the support identity, so a silent no-op must not look like success.
$KC get "roles/$ROLE" -r "$REALM" --fields name,composite,clientRole
