#!/usr/bin/env bash
# Copies the generated Keycloak e-mail theme from ORISO-Frontend into this image.
#
# The theme is generated from the ORISO e-mail design system
# (ORISO-Frontend `src/emails/`, `npm run emails:keycloak`) and reviewed there
# as a diff. Keycloak gets its own flavour because it resolves copy through a
# message bundle and supplies its own model variables; see ADR-020.
#
#   scripts/sync-email-theme.sh [path-to-ORISO-Frontend]
set -euo pipefail

frontend="${1:-../ORISO-Frontend}"
src="$frontend/src/emails/dist/keycloak/email"

if [[ ! -d "$src" ]]; then
  echo "no generated theme at $src — run 'npm run emails:keycloak' in $frontend" >&2
  exit 1
fi

target="$(cd "$(dirname "$0")/.." && pwd)/keycloak-image/themes/oriso/email"
mkdir -p "$target"
cp -R "$src/." "$target/"

echo "synced $(find "$target" -type f | wc -l | tr -d ' ') files into keycloak-image/themes/oriso/email"
echo "the same theme also lives in ORISO-Helm — run its copy of this script too,"
echo "or one of them silently wins at deploy time."
