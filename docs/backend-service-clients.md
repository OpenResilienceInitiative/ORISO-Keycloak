# Backend service clients

The current task-specific contract is [Task command identities](task-commands.md). Fresh realm imports disable `backend-technical`, `backend-admin`, their linked service accounts and the historical password users. They have no runtime management or OTP grants. The interactive `user-service` client retains human behavior with service accounts disabled.

Four provider actors use exact client credentials: account provisioning, account maintenance, account OTP and SMTP synchronization. Other workload actors have explicit receiving-service audiences and no native stock administration permissions. Realm export secrets are omitted; Helm supplies independent managed credentials and reconciles actual service-account ownership. Task scopes retain only the audited native `basic` scope, explicit realm-role mapper and explicit audiences.

Existing realms require staged receiver/client/caller rollout. Legacy actors remain until operator-approved retirement after exact subject ownership and consumer readback. Migration-only OTP compatibility is off by default and checks only the configured legacy client and its actual native service account with the verified historical role closure. It cannot authorize account or SMTP commands.

The historical `scripts/test-backend-service-clients.py` probe describes the prior enabled two-client baseline and must only run against a preserved legacy fixture. It is superseded for current task delivery by `scripts/test-task-command-permissions.py`, which tests both strict default-off and opt-in compatibility using real Keycloak-issued tokens.

Native requested-subject Magic Link exchange remains unsupported by the pinned configuration; this change grants no impersonation rights and does not claim that flow works.
