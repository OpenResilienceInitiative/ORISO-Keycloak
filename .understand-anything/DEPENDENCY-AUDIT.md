# Configuration and Dependency Audit

## Navigation

- [Runtime](#runtime)
- [Kubernetes resources](#kubernetes-resources)
- [Realm dependencies](#realm-dependencies)
- [Scripts](#scripts)
- [Current working tree note](#current-working-tree-note)

## Runtime

The runtime image is `quay.io/keycloak/keycloak:20.0.5`. The Deployment starts it with `start-dev`, which is suitable for development/testing but should be replaced for production.

Current env values in `keycloak-deployment.yaml`:

- `KEYCLOAK_ADMIN`
- `KEYCLOAK_ADMIN_PASSWORD`
- `KC_PROXY=edge`
- `KC_HOSTNAME=auth.oriso.site`
- `KC_HOSTNAME_STRICT_HTTPS=true`
- `KC_HTTP_ENABLED=true`

## Kubernetes Resources

- `keycloak-deployment.yaml`: Deployment with one replica, host networking, no resources, no probes, and live cluster metadata/status.
- `keycloak-service.yaml`: ClusterIP Service exposing ports 8080 and 8443, with live ClusterIP and metadata/status.
- `ingress.yaml`: Ingress for `auth.oriso.site` with cert-manager issuer `letsencrypt-prod`.

## Realm Dependencies

The realm depends on OIDC and OAuth2 defaults built into Keycloak. No external identity providers, groups, custom SPI providers, themes, or external user federation providers are configured in this repository.

## Scripts

`configure-http-access.sh` and `backup/realm-backup.sh` require:

- `kubectl` access to namespace `caritas`.
- A running pod labeled `app=keycloak`.
- Keycloak Admin CLI available inside the container.
- `jq` for backup JSON validation.

## Current Working Tree Note

`realm.json` is already modified in the working tree: service accounts are enabled for `admin-cli` and `app` compared with HEAD. This analysis used the current working tree state and did not revert that change.
