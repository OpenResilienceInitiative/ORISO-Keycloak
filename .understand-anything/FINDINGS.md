# Security Findings and Cleanup Register

## Navigation

- [High impact](#high-impact)
- [Hardcoded secrets](#hardcoded-secrets)
- [Weak defaults](#weak-defaults)
- [Environment inconsistencies](#environment-inconsistencies)
- [Unclear mappings](#unclear-mappings)
- [Missing safeguards](#missing-safeguards)

## High Impact

1. `keycloak-deployment.yaml` runs Keycloak with `start-dev`; this is not a production Keycloak runtime mode.
2. `KEYCLOAK_ADMIN` and `KEYCLOAK_ADMIN_PASSWORD` are hardcoded in `keycloak-deployment.yaml` and both scripts use `admin/admin` for kcadm.
3. The `app` client allows wildcard redirect URI `*` and wildcard web origin `*`.
4. `app` and `admin-cli` have direct access grants enabled; both also have service accounts enabled in the current working tree diff.
5. Brute force protection is disabled, password policy is absent, and event/admin-event logging is disabled in `realm.json`.

## Hardcoded Secrets

- `keycloak-deployment.yaml` contains admin credentials directly in env values.
- `configure-http-access.sh` authenticates to kcadm with static admin credentials.
- `backup/realm-backup.sh` authenticates to kcadm with static admin credentials.
- Documentation examples use placeholder passwords; those are acceptable as examples only if not copied into manifests.

## Weak Defaults

- Access token lifespan is 18000 seconds.
- `revokeRefreshToken` is false.
- `bruteForceProtected` is false.
- `passwordPolicy` is not configured.
- `verifyEmail` is false and SMTP config is empty, so email-based flows need operational review.
- `eventsEnabled`, `adminEventsEnabled`, and `adminEventsDetailsEnabled` are false.
- `default-roles-online-beratung` grants `offline_access` by default.

## Environment Inconsistencies

- `realm.json` currently has `sslRequired=external`, while `README.md`, `DEPLOYMENT.md`, `STATUS.md`, and `configure-http-access.sh` describe `sslRequired=NONE` for HTTP access.
- Docs reference public IP and Nginx `/auth` paths; ingress uses `auth.oriso.site` at `/`.
- `keycloak-service.yaml` includes live-cluster metadata and a concrete ClusterIP. Desired-state manifests normally omit generated status, uid, resourceVersion, and clusterIP unless fixed IP is intentional.
- `keycloak-deployment.yaml` includes live deployment status and last-applied annotations, not just desired state.

## Unclear Mappings

- Groups are empty, so group-based IAM is not used here despite Keycloak group mappers existing in optional scopes.
- There are no backend confidential clients. Backend services appear to act only as resource servers, which should be documented as the intended model.
- `USER_ADMIN` and `user-admin` both exist as realm roles; this naming overlap should be documented or consolidated.
- Tenant isolation depends on a `tenantId` user attribute. This repository does not show provisioning rules that ensure it is always present and correct.

## Missing Safeguards

- No Kubernetes readiness/liveness probes.
- No resource requests/limits.
- No external database configuration in the Deployment.
- No Kubernetes Secrets for admin or database credentials.
- No automated realm import job or backup CronJob in this repository.
- No documented rollback path for realm changes beyond manual backups.
