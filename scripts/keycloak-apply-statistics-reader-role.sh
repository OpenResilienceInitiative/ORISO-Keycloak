#!/bin/bash
# Creates the read-only statistics realm role (ORISO-UserService#1666) in an
# EXISTING realm. Fresh imports get it from realm.json. Idempotent: an existing
# role is left alone, and the script fails if it ever became composite.
#
#   kubectl -n <ns> exec deploy/keycloak -- bash -s < scripts/keycloak-apply-statistics-reader-role.sh
#
# Log kcadm in first, interactively, so no password lands in argv or shell
# history:  kcadm.sh config credentials --server <url> --realm master --user <admin>
# The script refuses to run without a valid kcadm session.
# Realm defaults to online-beratung (override: REALM).
# The role is assigned ONLY by UserService when a platform admin creates a
# Statistik-Leser; never add it to a default role or group.
set -euo pipefail

KC=/opt/keycloak/bin/kcadm.sh
REALM="${REALM:-online-beratung}"
ROLE=statistics-reader
ROLE_JSON="$(mktemp)"
trap 'rm -f "$ROLE_JSON"' EXIT

if ! $KC get "realms/$REALM" --fields realm > /dev/null 2>&1; then
  echo "ERROR: kcadm is not logged in (or realm $REALM does not exist)." >&2
  echo "Run: $KC config credentials --server <url> --realm master --user <admin>" >&2
  exit 1
fi

if $KC get "roles/$ROLE" -r "$REALM" > "$ROLE_JSON" 2>/dev/null; then
  echo "role $ROLE already exists in $REALM"
else
  $KC create roles -r "$REALM" -s "name=$ROLE" \
    -s 'description=Read-only platform statistics and CSV export; created by platform admins only (ORISO-UserService#1666)'
  echo "created role $ROLE in $REALM"
  $KC get "roles/$ROLE" -r "$REALM" > "$ROLE_JSON"
fi

if tr -d ' \n' < "$ROLE_JSON" | grep -q '"composite":true'; then
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
