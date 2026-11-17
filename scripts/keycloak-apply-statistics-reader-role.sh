#!/bin/bash
# Creates the read-only statistics realm role (ORISO-UserService#1666) in an
# EXISTING realm. Fresh imports get it from realm.json. Idempotent: an existing
# role is left alone, and the script fails if it ever became composite.
#
#   kubectl -n <ns> exec deploy/keycloak -- bash -s < scripts/keycloak-apply-statistics-reader-role.sh
#
# Requires admin credentials; export KC_ADMIN_USER / KC_ADMIN_PASSWORD first or
# log kcadm in beforehand. Realm defaults to online-beratung (override: REALM).
# The role is assigned ONLY by UserService when a platform admin creates a
# Statistik-Leser; never add it to a default role or group.
set -euo pipefail

KC=/opt/keycloak/bin/kcadm.sh
REALM="${REALM:-online-beratung}"
ROLE=statistics-reader
KC_SERVER="${KC_SERVER:-http://localhost:8080${KC_HTTP_RELATIVE_PATH:-}}"

if [ -n "${KC_ADMIN_USER:-}" ]; then
  $KC config credentials --server "$KC_SERVER" --realm master \
    --user "$KC_ADMIN_USER" --password "$KC_ADMIN_PASSWORD"
fi

if $KC get "roles/$ROLE" -r "$REALM" > /tmp/statistics-reader-role.json 2>/dev/null; then
  echo "role $ROLE already exists in $REALM"
else
  $KC create roles -r "$REALM" -s "name=$ROLE" \
    -s 'description=Read-only platform statistics and CSV export; created by platform admins only (ORISO-UserService#1666)'
  echo "created role $ROLE in $REALM"
  $KC get "roles/$ROLE" -r "$REALM" > /tmp/statistics-reader-role.json
fi

if tr -d ' \n' < /tmp/statistics-reader-role.json | grep -q '"composite":true'; then
  echo "ERROR: $ROLE is composite; it must not grant any other role" >&2
  exit 1
fi

DEFAULT_ROLE="default-roles-$REALM"
if $KC get "roles/$DEFAULT_ROLE/composites/realm" -r "$REALM" 2>/dev/null \
    | tr -d ' \n' | grep -q "\"name\":\"$ROLE\""; then
  echo "ERROR: $ROLE is part of $DEFAULT_ROLE; every new account would get it" >&2
  exit 1
fi
echo "ok: $ROLE is a plain realm role and not granted by default"
