# ORISO-Keycloak Understand-Anything Notes

> Scope: generated from ORISO-Keycloak only. Parent folders and sibling repositories were not analyzed.

## Navigation

- [Knowledge graph](knowledge-graph.json)
- [IAM architecture](ARCHITECTURE.md)
- [Developer and DevOps onboarding](ONBOARDING.md)
- [ORISO ecosystem integration](ORISO-ECOSYSTEM.md)
- [Security findings](FINDINGS.md)
- [Configuration and dependency audit](DEPENDENCY-AUDIT.md)
- Visuals: [auth flow](visuals/auth-flow.mmd), [token flow](visuals/token-flow.mmd), [deployment flow](visuals/deployment-flow.mmd), [realm map](visuals/realm-map.mmd), [ecosystem flow](visuals/ecosystem-flow.mmd)

## Dashboard

Knowledge graph saved at: /Users/nikunjchampakbhairohit/Developer/freelance/Germany/Oriso-frank-client/ORISO/ORISO-Keycloak/.understand-anything/knowledge-graph.json

Open the dashboard with:

```bash
cd /Users/nikunjchampakbhairohit/.understand-anything/repo/understand-anything-plugin/packages/dashboard && GRAPH_DIR="/Users/nikunjchampakbhairohit/Developer/freelance/Germany/Oriso-frank-client/ORISO/ORISO-Keycloak" pnpm exec vite --host 127.0.0.1
```

Then open the local URL printed by Vite.

## Quick Map

ORISO-Keycloak provides the central IAM configuration for ORISO. It defines the `online-beratung` realm, OIDC clients, realm roles, token claims, authentication flows, required actions, and Kubernetes runtime manifests.

- Realm: `online-beratung`.
- Main application client: `app`.
- Tenant isolation signal: `tenantId` user attribute mapped into tokens by `app-custom`.
- Authorization signal: realm roles emitted through `realm_access.roles`.
- Backend integration: services validate issuer/JWK and map JWT claims into service permissions.
- Runtime: Kubernetes Deployment/Service/Ingress in namespace `caritas`.

## Graph Stats

- Files scanned: 10
- Graph nodes: 152
- Graph edges: 247
- Clients: 7
- Realm roles: 13
- Client scopes: 11
- Authentication flows: 18

## Important Files

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
