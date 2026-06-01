# ORISO-Keycloak Onboarding

## Navigation

- [First hour](#first-hour)
- [Local run](#local-run)
- [Kubernetes run](#kubernetes-run)
- [Developer integration](#developer-integration)
- [DevOps checklist](#devops-checklist)
- [Change workflow](#change-workflow)

## First Hour

Read files in this order:

1. `realm.json` - Current Keycloak realm export for online-beratung. Contains clients, roles, scopes, flows, token settings, and required actions.
2. `keycloak-deployment.yaml` - Kubernetes Deployment for Keycloak 20.0.5 runtime, admin env vars, hostNetwork, hostname, and HTTP settings.
3. `keycloak-service.yaml` - ClusterIP Service exposing Keycloak HTTP 8080 and HTTPS 8443.
4. `ingress.yaml` - Ingress and TLS configuration for auth.oriso.site.
5. `configure-http-access.sh` - Post-deployment kcadm script that disables SSL requirement for master and all realms.
6. `backup/realm-backup.sh` - Realm export/backup script that updates backup files and realm.json.
7. `DEPLOYMENT.md` - Deployment options, environment variables, database notes, SSL/TLS guidance, verification, and security checklist.
8. `README.md` - Repository overview and ORISO service integration examples.
9. `STATUS.md` - Operational status, access points, integration status, known issues, and maintenance schedule.
10. `realm.json.backup-http` - Backup copy of the realm export used for HTTP-access recovery/comparison.

Then open the graph dashboard and follow the tour from `realm.json` to the app client, token claims, Kubernetes manifests, and security findings.

## Local Run

The simplest local run imports `realm.json` into Keycloak dev mode:

```bash
docker run --rm \
  --name oriso-keycloak \
  -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  -v "$(pwd)/realm.json:/opt/keycloak/data/import/realm.json" \
  -p 8080:8080 \
  quay.io/keycloak/keycloak:20.0.5 start-dev --import-realm
```

Local URLs:

- Admin console: `http://localhost:8080/admin/`
- Realm metadata: `http://localhost:8080/realms/online-beratung/.well-known/openid-configuration`
- Token endpoint: `http://localhost:8080/realms/online-beratung/protocol/openid-connect/token`

For local frontend login, the `app` client already allows `http://localhost:9000/*` redirects.

## Kubernetes Run

Apply manifests from this repository only:

```bash
kubectl apply -f keycloak-service.yaml
kubectl apply -f keycloak-deployment.yaml
kubectl apply -f ingress.yaml
```

Then verify:

```bash
kubectl get pods -n caritas -l app=keycloak
kubectl logs -n caritas deployment/keycloak --tail=100
kubectl get svc -n caritas keycloak
```

If the environment intentionally terminates TLS before Keycloak and needs HTTP realm behavior, run:

```bash
./configure-http-access.sh
```

## Developer Integration

Frontend/admin applications use Keycloak with:

- URL: the environment Keycloak base URL.
- Realm: `online-beratung`.
- Client ID: `app`.

Backend services validate tokens with:

- Issuer URI: `<keycloak-base>/realms/online-beratung`.
- JWK set URI: `<keycloak-base>/realms/online-beratung/protocol/openid-connect/certs`.

After validation, services should read:

- `realm_access.roles` for role-driven authorization.
- `tenantId` for tenant isolation.
- `userId` and `username` for user context.

## DevOps Checklist

- Move admin credentials to Kubernetes Secrets before production use.
- Replace `start-dev` with production Keycloak startup and an external database.
- Add readiness/liveness probes and resource requests/limits.
- Remove `hostNetwork` unless there is a documented networking requirement.
- Align `sslRequired` behavior across `realm.json`, scripts, docs, and ingress/TLS setup.
- Narrow `app` redirect URIs and web origins.
- Enable brute force protection, password policy, event logging, and admin event logging.
- Decide whether direct access grants are truly required for `app` and `admin-cli`.

## Change Workflow

1. Export the current realm from the admin console or `backup/realm-backup.sh`.
2. Review `git diff realm.json` carefully.
3. Check for secrets, wildcard origins, unwanted roles, and token lifespan changes.
4. Update `.understand-anything/` docs if the IAM model changes.
5. Test login, token validation, and at least one tenant-aware backend request.
