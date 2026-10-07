# Frozen wire contract v1 — P2/P4 coordination (confirm adapter matches before merge)
Base /realms/{realm}/oriso-commands/v1. Content-Type application/json.
Authorization: Bearer <task access token>; aud must contain oriso-task-commands.
Task IDs backend-account-provisioning / backend-account-maintenance /
backend-account-otp / backend-smtp-sync; roles account-provisioning /
account-maintenance / otp-config-admin / smtp-sync. Narrow read role account-read
on actual provisioning/maintenance tasks. Env IDENTITY_<TASK>_CLIENT_ID,
IDENTITY_<TASK>_SERVICE_SUBJECT caller-side. Provider derives subject from client.

Account requests additionally X-ORISO-Origin-Authorization: compact JWT HS256.
Managed keys ORISO_PROVISIONING_ORIGIN_KEY and ORISO_MAINTENANCE_ORIGIN_KEY are
standard Base64 encoded >=32 random bytes, distinct from each other/client secrets.
JWT header {alg:HS256,typ:JWT}; claim fields EXACTLY iss,aud,iat,exp,jti,purpose,
operation,taskClient,taskSubject,originKind,originAction,target,tenantId,roles,
payloadDigest. iss=oriso-userservice; aud=oriso-task-commands;
purpose=oriso-command; exp>now, exp>iat, exp-iat<=60, now-60<=iat<=now+5; unique jti UUID.
originKind INVITATION|REGISTRATION|ANONYMOUS|HUMAN_ADMIN|SELF_SERVICE|LIFECYCLE|IMPORT|ONBOARDING|PASSWORD_RESET.
originAction must equal operation. target=attempt UUID for create/commit/compensate/creation-recover,
account ID for account operations; exact query value for email/username search.
tenantId string or null; roles array of allowed human realm-role names.
payloadDigest = base64url(no padding)(HMAC-SHA256(key,
UTF8('payload\n'+canonicalJson(command)))). Canonical JSON recursively sorts object
keys, compact encoding, arrays preserve order, only strings/booleans/null/integer
values, no floating values. Include every field sent; no proof field in body.
Receipt = base64url HMAC-SHA256(provisioning key,
UTF8('receipt\n'+realmId+'\n'+attemptId+'\n'+ownerSubject+'\n'+accountId)).
JWT signature standard base64url header+'.'+base64url payload with same origin key.
Keys purpose-separated by input prefix; compare constant-time. No secrets in logs.

| Operation claim | HTTP | Command body / projection |
|---|---|---|
| account.create | PUT /account-creations/{attemptId} | {username,email,firstName,lastName,preferredLanguage,tenantId,password,passwordTemporary,roles:[...],registrationKind} |
| account.creation-recover | POST /account-creations/{attemptId}/recovery-claims | {registrationKind} |
| account.commit | POST /account-creations/{attemptId}/commit | {accountId,creationProof} |
| account.compensate | POST /account-creations/{attemptId}/compensations | {accountId,creationProof} |
| account.read | GET /accounts/{id} | proof digest over {} |
| account.search | GET /accounts/search?username=exact OR email=exact | proof digest over {username:exact} OR {email:exact} |
| account.profile | PATCH /accounts/{id}/profile | {username,email,firstName,lastName,tenantId,preferredLanguage} (only sent fields change) |
| account.password | PUT /accounts/{id}/password | {password,passwordTemporary} |
| account.roles | PUT /accounts/{id}/roles | {roles:[...]} |
| account.deactivate | POST /accounts/{id}/deactivation | {} |
| account.delete | DELETE /accounts/{id} | proof digest over {} |
| account.inventory | POST /account-inventory | {cutoff:ISO-8601 Instant,first:int>=0,max:int1..1000} |
| account.lifecycle-status | GET /accounts/{id}/lifecycle-status | proof digest over {} |
| account.suspend | POST /accounts/{id}/suspension | {} |
| account.restore | POST /accounts/{id}/access-restoration | {enabled:boolean} |
| SMTP no origin header | PUT /smtp | {revision,globalSmtpEnabled,globalFeatureSystemNotificationEmailsEnabled,globalSmtpHost,globalSmtpPort,globalSmtpFrom,globalSmtpUsername,globalSmtpPassword,globalSmtpSecure} |

Create returns HTTP201 {attemptId,accountId,creationProof,status:OPEN}, replay200 same
receipt; commit204; compensate204 repeated legitimate tombstone remains204;
committed compensation409; foreign/forged403; changed attempt payload409.
OPEN accounts remain native enabled=false until the first valid OPEN commit.
That commit atomically enables only the owned account and marks COMMITTED.
Repeated COMMITTED commit is a no-op and never undoes a later independent disable.
Recovery/compensation never activate an account.

Recovery claims return HTTP200 {attemptId,accountId,creationProof,status}.
OPEN atomically becomes RECOVERY_CLAIMED, retaining the exact original receipt;
old create/commit then409. Owned compensation remains idempotent.
Absent attempt creates an owner-bound ABANDONED tombstone with explicit null
accountId/creationProof, fencing any delayed create409 without account mutation.
Existing COMMITTED/COMPENSATED status is diagnostic; COMMITTED never compensates.
Registration kind in the body is taken from the durable caller journal and bound
by the unchanged signed payloadDigest. Provider compares original persisted
registrationKind, tenant, initial role set, originKind, task client and subject.
Absent tombstones validate the same createKind/role/origin policy before capture.
No username search, foreign receipt, arbitrary deletion or new JWT claim exists.
Concurrent ownership insertion may return409; retry reads the durable winner.
Rows predating the origin/initial-role migration cannot be recovered by guessing
missing authority; operational migration must explicitly drain those attempts.
Projection HTTP200 {id,username,email,firstName,lastName,tenantId,preferredLanguage,
enabled,emailVerified,roles:[...],passwordChangeRequired:boolean}; absent404.
Search returns array [] or bounded matching projections (exact matches only), no
wildcards, arbitrary attrs, credentials or capability/receipt leakage.
Maintenance204, delete absent204, SMTP200 {revision,status}; status APPLIED or DISABLED_OR_INCOMPLETE.

registrationKind ASKER|ANONYMOUS|CONSULTANT|AGENCY_ADMIN|CONSULTANT_AGENCY_ADMIN|TENANT_ADMIN.
Create/profile tenantId JSON type is string or null; caller domain Long is converted at the wire adapter before payload signing.
Creator sets userId=created ID, username/userName decoded username, locale=language,
optional tenantId; enabled=false until first valid commit, emailVerified=true.
Kinds require respectively: user; user; consultant; restricted-agency-admin+user-admin;
consultant+restricted-agency-admin+user-admin; user-admin+agency-admin+tenant-admin.
Optional group-chat-consultant for consultant kinds and topic-admin for TENANT_ADMIN only, as limited by signed origin role authority.
Signed roles limit DTO roles; no task actor inherits these human roles.
SELF_SERVICE authorizes only account.read/account.profile/account.password for its verified own target; it cannot change tenant. HUMAN_ADMIN
limited signed tenant/role permissions; LIFECYCLE only read/search/deactivate/delete/dummy-email profile and the bounded inactivity inventory/status/suspend/restore actions below, never create/roles/password.
OTP paths unchanged, strict default guard bound to backend-account-otp + otp-config-admin;
no stock management permission. Magic Link exchange remains baseline unsupported.

Additional proven invitation kind: CONSULTANT_AGENCY_ADMIN. Allowed initial human roles consultant, group-chat-consultant, restricted-agency-admin, user-admin; required consultant/restricted-agency-admin/user-admin. Origin INVITATION or HUMAN_ADMIN only. This is one atomic provisioning command, not a maintenance role grant.

Migration-only OTP compatibility: ORISO_LEGACY_OTP_COMPATIBILITY default false; opt-in true only after operator verifies pinned legacy ownership. ORISO_LEGACY_OTP_CLIENT_ID default backend-admin. Resolve actual client service-account subject server-side, require exact azp/sub/direct+token otp-config-admin and verified native aud realm-management. Permit only existing direct realm-management manage-users/view-users/query-users/view-realm and their verified native26.6.3 query-groups closure; reject all other management/human roles. This grants no role and applies only to existing OTP operations, never account/SMTP commands. Disable after caller cutover before retirement. Password users cannot use fallback. New OTP/task actor always takes strict branch even when compatibility is on.

Actual anonymous registration uses human role user (no anonymous realm role). ASKER/ANONYMOUS missing or blank email is completed atomically after generated account ID using managed ORISO_IDENTITY_DUMMY_EMAIL_SUFFIX (Helm global.identityDummyEmailSuffix, same as UserService IDENTITY_EMAIL_DUMMY_SUFFIX). No caller-controlled suffix. Provider validates native completed profile before transaction commit; projection returns derived address.
Native26.6.3 minimal basic scope is retained: task defaultScopes [basic], optional[]; basic contains only auth_time and sub mappers, no role scope grants. Old export20.0.5 migrates through MigrateTo25_0_0 basic all-client attachment; human explicit scope arrays remain unchanged.

IMPORT proof authorizes CONSULTANT-only initial creation (consultant plus optional group-chat-consultant), commit and compensation through the account-provisioning transport. On the separate account-maintenance transport it permits only exact existing Consultant read and additive consultant/group-chat-consultant roles as specified below; no search, profile, password, delete or deactivation. backend-consultant-import itself has only receiving userservice audience and consultant-import role.

Protected tenant0 accounts with an effective tenant-admin realm role (direct, composite or inherited group) allow target-bound SELF_SERVICE account.read/account.profile/account.password, PASSWORD_RESET account.read/account.password, and read-only LIFECYCLE status/inventory proofs. UserService must establish actual verified human JWT.sub == target before issuing this proof; roles and tenant movement remain denied, and HUMAN_ADMIN/LIFECYCLE mutations/search/delete/deactivation retain platform protection.

Legacy OTP native harmless default closure is limited to offline_access, uma_authorization, account.manage-account/view-profile and manage-account-links. Token realm roles must still be exactly otp-config-admin; only realm-management audience and the verified native five management token roles are accepted. All other direct/effective task, human, group, client and management grants fail closed. This creates no grants.

ONBOARDING is limited to account.read/account.password. UserService must hold or consume the verified one-time setup claim, bind its persisted target/tenant, and verify the existing initial-password authority before signing password change. No ambient/missing-request fallback, arbitrary body target, or other operation is accepted. ONBOARDING cannot access protected platform targets. Creation attempts persist registrationKind and tenant with ownership; IMPORT commit/compensation accepts only the original CONSULTANT attempt and matching tenant.

PASSWORD_RESET allows only account.read/account.password, including the existing protected tenant0 platform-admin recovery. UserService must consume/verify the existing reset token, preserve existing MFA/OTP guards, and derive the exact persisted subject/tenant; no caller body target or no-JWT SELF_SERVICE fallback. All reset profile/role/tenant/deletion/deactivation operations are rejected. Valid signed same-body transport retries within the proof lifetime are intentional; consumed one-time domain claims cannot mint a new authority again (UserService responsibility).

Existing CSV Consultant maintenance extension: IMPORT on account-maintenance transport + maintenance origin key permits only account.read/account.roles for an existing native consultant and exact captured/persisted row tenant. DTO roles is the full desired bounded HUMAN_ROLES set; proof roles is only consultant/group-chat-consultant additions. Receiver requires every current human role preserved, additions only those two roles and included in proof, then adds without deleting mappings. Admin addition/removal, profile/password/search/delete/deactivation and platform/service targets remain denied. Provisioner IMPORT still permits only CONSULTANT create/commit/compensate/recovery. AccountProjection.roles always excludes default/offline/uma/task roles.

Read-only inactivity orphan inventory: POST /account-inventory {cutoff:ISO-8601 Instant,first:int>=0,max:int1..1000}. Maintenance-key LIFECYCLE proof only, target cutoff:<cutoff>/first:<first>/max:<max>, tenantId:null,roles:[]; US factory reads actual immutable account_inactivity_rollout id=1 cutoff inside the existing FOR UPDATE transaction, never caller-provided authority. Response {accounts:[{id,tenantId,createdTimestamp,eligibleHuman}],hasMore:boolean}; original native page length==max determines hasMore, so technical-only pages do not truncate scan. No names/email/roles/credentials/filter/realm input. Actual service accounts and effective pure machine identities are ineligible; native realm/client HUMAN_ROLES preserve mixed technical-human and platform-human enrollment and missing-snapshot diagnostics. Inventory grants no mutation authority; protected-target command guard remains independent.

Bounded native inactivity effects: GET /accounts/{id}/lifecycle-status (account.lifecycle-status, digest {}) returns {enabled:boolean,sessionCount:integer,roles:[ASKER|CONSULTANT|OTHER|UNKNOWN]}. POST /accounts/{id}/suspension (account.suspend, {}) disables the native account, invalidates not-before and performs native backchannel logout, confirms disabled/no active sessions. POST /accounts/{id}/access-restoration (account.restore, {enabled:boolean}) restores only original enabled state from the UserService durable access-state record. All require maintenance-key LIFECYCLE proof exact target/tenant and empty roles. Issuer reads actual persisted inactivity row: SUSPENDING/DELETING for suspension, REACTIVATING plus durable original enabled for restoration. No arbitrary caller boolean authority or profile/role rights. Read-only status preserves platform humans and returns UNKNOWN for service accounts; service/protected-platform mutations remain denied. Coarse roles derive actual effective native realm/client/group roles; only known default/account infrastructure is skipped; local consultant/admin records remain UserService responsibility.

## Local verification

The PR workflow builds the provider image and runs both default-off and explicit legacy OTP compatibility cases against disposable Keycloak 26.6.3. Tests use native token issuance and HTTP endpoints, not mocked bearer validation. They cover exact client/subject/audience/role binding, stock-admin denial, profile/password validation, inherited group/client role classification, SMTP revisions, creation races, durable receipts/tombstones and database-preserving restart. Synthetic secrets remain in memory; fixtures remove their own containers.

```sh
python3 -m unittest discover -s tests -q
mvn -f keycloak-image/pom.xml test
docker build --tag oriso-keycloak:permission-contract keycloak-image
python3 scripts/test-task-command-permissions.py --image oriso-keycloak:permission-contract
python3 scripts/test-task-command-permissions.py --image oriso-keycloak:permission-contract --legacy-otp-compatibility
```

This verifies the actual custom image against its embedded H2 database locally. MariaDB rollout, remote image publication, live caller readback, legacy retirement and deployed browser flows are separate delivery gates. Managed origin keys and task client secrets must come from deployment Secrets; never include them in the realm export, command events or logs.

First import and existing-realm reconciliation are owned by ORISO-Helm. Receiver first, dedicated clients next, callers next; exact legacy OTP compatibility may be explicitly enabled during that sequence and must then be removed. Retirement remains operator-gated after verified caller readback.

The optional local joined gate keeps the disposable custom provider alive while running UserService `IdentityCreationNativeRestartIT` with its real durable creation journal and command adapter. Invoke `scripts/test-task-command-permissions.py --image <custom-image> --userservice-receiver <existing-UserService-checkout> --userservice-java-home <Java-21-home>`. `ORISO_CREATION_NATIVE_FIXTURE` points only to a mode-0600 temporary synthetic fixture; the harness removes it after Maven and removes its container in the outer finally block. Successful exit is insufficient: the harness requires a fresh explicit suite report with executed cases and zero failures/errors/skips. Ordinary single-repository test selection excludes this fixture-dependent class. Required cross-repository CI must invoke the joined gate against immutable provider and UserService commits; it does not substitute for the full native permission suite or deployment/browser acceptance.
