# ORISO-Keycloak IAM Architecture

## Navigation

- [Responsibility](#responsibility)
- [Realm model](#realm-model)
- [Client model](#client-model)
- [Authentication flows](#authentication-flows)
- [Authorization flows](#authorization-flows)
- [Tenant isolation](#tenant-isolation)
- [Token flow](#token-flow)
- [SSO and identity providers](#sso-and-identity-providers)
- [Deployment structure](#deployment-structure)

## Responsibility

This repository owns the Keycloak configuration used by ORISO for identity, authentication, authorization, and token issuance. It does not contain application code; its behavior is defined by realm exports, Kubernetes manifests, shell automation, and operations documentation.

## Realm Model

`realm.json` defines the `online-beratung` realm. The realm is enabled and currently has `sslRequired` set to `external` in the checked working tree. Documentation and `configure-http-access.sh` describe setting `sslRequired=NONE` after deployment for HTTP behind a proxy, so this environment contract needs to be kept explicit.

Important realm settings from `realm.json`:

- Access token lifespan: 18000 seconds.
- SSO session idle timeout: 1800 seconds.
- SSO session max lifespan: 36000 seconds.
- Refresh token revocation: disabled.
- Brute force protection: disabled.
- Password policy: absent.
- SMTP server: absent.
- Identity providers: none configured.
- Groups: none configured.
- Signature algorithm: RS256.

## Client Model

The realm exports seven clients:

- `app`: main ORISO frontend/admin client. Public OIDC client with standard flow enabled, direct access grants enabled, service accounts currently enabled in the working tree, wildcard redirect URI, and wildcard web origin.
- `admin-cli`: Keycloak admin CLI client. Public client with direct access grants enabled and service accounts currently enabled in the working tree.
- `account` and `account-console`: built-in account management clients.
- `security-admin-console`: built-in admin console client.
- `realm-management` and `broker`: built-in bearer-only internal clients.

The only ORISO-specific client in this export is `app`. Backend services are not represented as confidential clients in this repository; they validate tokens as resource servers using the realm issuer and JWK set.

## Authentication Flows

Top-level realm flows:

- Browser flow: cookie check, SPNEGO disabled, identity provider redirector, then forms flow.
- Forms flow: username/password form with conditional OTP.
- Direct grant flow: username validation, password validation, and conditional OTP.
- Registration flow: built-in registration form, but realm registration is disabled.
- Reset credentials flow: choose user, email, reset password, conditional OTP, but reset password is disabled.
- Client flow: client-secret, client-jwt, client-secret-jwt, and x509 authenticators are alternatives.

## Authorization Flows

Authorization is role-driven. `roles` client scope maps realm roles into `realm_access.roles` in access tokens. ORISO services then map those roles to service-local permissions.

Realm roles exported in `realm.json` include:

- `tenant-admin`
- `single-tenant-admin`
- `agency-admin`
- `consultant`
- `user`
- `user-admin`
- `topic-admin`
- `technical`
- `TECHNICAL_DEFAULT`
- `USER_ADMIN`
- Keycloak built-ins: `offline_access`, `uma_authorization`, and `default-roles-online-beratung`.

`default-roles-online-beratung` is composite and grants `offline_access`, `uma_authorization`, and account client roles `manage-account` and `view-profile`.

## Tenant Isolation

Tenant isolation is not modeled through Keycloak groups in this export. Instead, `app-custom` maps the Keycloak user attribute `tenantId` into the `tenantId` claim in access token, ID token, and userinfo response.

Backend services must enforce tenant isolation after token validation. For example, tenant-aware services compare the token `tenantId` claim with the requested tenant context and then combine that with realm roles.

## Token Flow

Frontend/admin flow:

1. The ORISO frontend initializes Keycloak with realm `online-beratung` and client `app`.
2. Browser login uses Keycloak's browser flow.
3. Keycloak issues tokens containing default scopes: `web-origins`, `acr`, `profile`, `roles`, `app-custom`, and `email`.
4. The frontend sends the access token as a bearer token to backend services.
5. Backends validate issuer/JWK and read `realm_access.roles`, `username`, `tenantId`, and `userId`.

Optional scopes include `address`, `phone`, `offline_access`, and `microprofile-jwt`.

## SSO and Identity Providers

Keycloak provides SSO within the `online-beratung` realm. `identityProviders` is empty, so this repository does not configure external SSO such as SAML, Azure AD, Google, or social login. The browser flow still includes the built-in identity-provider redirector, but there are no providers to redirect to.

## Deployment Structure

- `keycloak-deployment.yaml`: Deployment named `keycloak` in namespace `caritas`, image `quay.io/keycloak/keycloak:20.0.5`, args `start-dev`, `hostNetwork: true`, `KC_PROXY=edge`, `KC_HOSTNAME=auth.oriso.site`, `KC_HOSTNAME_STRICT_HTTPS=true`, `KC_HTTP_ENABLED=true`.
- `keycloak-service.yaml`: ClusterIP Service exposing 8080 and 8443.
- `ingress.yaml`: Ingress for `auth.oriso.site` with TLS secret `auth-oriso-site-tls` and cert-manager issuer `letsencrypt-prod`.
- `configure-http-access.sh`: post-deployment script to set SSL requirement to NONE.
- `backup/realm-backup.sh`: exports the realm from the running pod and updates `realm.json`.
