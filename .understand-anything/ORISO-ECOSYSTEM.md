# ORISO Ecosystem Integration

## Navigation

- [Role in ORISO](#role-in-oriso)
- [Frontend and admin](#frontend-and-admin)
- [Backend services](#backend-services)
- [Tenant-aware services](#tenant-aware-services)
- [Operational boundary](#operational-boundary)

## Role in ORISO

ORISO-Keycloak is the identity provider for the ORISO platform. It does not implement business logic; it issues tokens that frontend, admin, and backend services use to authenticate users and authorize actions.

## Frontend and Admin

Frontend/admin clients authenticate against realm `online-beratung` and client `app`. The browser flow performs login and returns tokens. The `app` client includes `app-custom` and `roles` as default scopes, so the frontend receives role and tenant/user context in tokens.

## Backend Services

Spring Boot services use Keycloak as an OAuth2 resource server. They validate JWTs through the realm issuer and JWK set, then map roles and custom claims locally.

Typical backend configuration:

```yaml
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: http://keycloak.caritas.svc.cluster.local:8080/realms/online-beratung
          jwk-set-uri: http://keycloak.caritas.svc.cluster.local:8080/realms/online-beratung/protocol/openid-connect/certs
```

## Tenant-Aware Services

Tenant-aware services rely on the token `tenantId` claim. Keycloak only emits the claim; backend services enforce access rules. This makes tenant isolation a shared contract between Keycloak profile data and backend authorization code.

Important implication: a user with missing or incorrect `tenantId` may authenticate successfully but fail tenant-aware service authorization, or worse, be authorized incorrectly if a service does not validate tenant context carefully.

## Operational Boundary

`keycloak-deployment.yaml`, `keycloak-service.yaml`, and `ingress.yaml` describe the platform identity runtime. `configure-http-access.sh` and `backup/realm-backup.sh` modify or export live cluster state. Treat this repository as both IAM configuration and infrastructure documentation.
