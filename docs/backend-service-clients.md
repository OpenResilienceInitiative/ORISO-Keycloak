# Backend service clients

This export supplies UserService#1351's separately scoped service accounts. Enable backend client-credentials acquisition before activating application-realm brute-force protection. Existing realms are reconciled in place; importing realm.json does not update them.

`backend-technical` has only the technical realm role. `backend-admin` has only otp-config-admin plus manage-users, view-users, query-users and view-realm (view-users also inherits query-groups). Neither client accepts browser or password grants. Each receives only its explicit role scope; no realm-admin or impersonation permission is added.

Secrets are deliberately omitted from the export. Keycloak generates independent unpredictable secrets during fresh import. The controlled bootstrap/reconciliation step sets configured KEYCLOAK_BACKEND_TECHNICAL_CLIENT_SECRET and KEYCLOAK_BACKEND_ADMIN_CLIENT_SECRET from deployment secrets, then reads actual service-account subjects for strict backend client/subject checks. Missing configured secrets must fail closed; never retain a password fallback.

Fresh imports use service UUIDs 12316d09-a9da-41b9-a13e-ee2c515800b5 (technical) and 615a7bf8-3e12-40c7-a949-f88640acea8e (admin). Existing realm service-account UUIDs may differ. Read them back; do not assume a realm reimport overwrites them. Retire legacy technical/svc-keycloak-admin password identities only after all callers switch successfully. They are disabled and lack credentials in the fresh export.

The current requested_subject exchange adapter preserves its public app-client request and Optional.empty refusal semantics. This migration does not create user-impersonation rights or enable a preview token-exchange implementation.

For developers — isolated verification (Docker, synthetic fixture only):

```sh
python3 -m unittest discover -s tests -p 'test_*.py'
python3 scripts/test-backend-service-clients.py --image <exact-keycloak-image-digest>
```

The runtime probe checks generated secrets without printing them, token subjects/client ids/roles, permission denials, disabled password grants, and uninterrupted service credentials while a disposable legacy password user is locked. Tokens and passwords remain in memory; every task container is removed.
