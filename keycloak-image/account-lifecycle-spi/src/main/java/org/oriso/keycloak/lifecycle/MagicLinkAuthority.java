package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;

import com.fasterxml.jackson.databind.JsonNode;
import java.time.Instant;
import java.util.*;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.models.UserModel;

/** Proof before locks, then current native issuer/target/profile under the owning transaction. */
final class MagicLinkAuthority {
  static final String NOTE = "oriso.magic-link.checked-command";
  private final LifecycleAuthorization auth;
  private final Map<String,Set<String>> groups;
  private MagicLinkAuthority(LifecycleAuthorization auth, Map<String,Set<String>> groups) {
    this.auth = auth;
    this.groups = Map.copyOf(groups);
  }
  static MagicLinkAuthority environment() {
    String enabled = System.getenv("ORISO_ACCOUNT_LIFECYCLE_ENABLED");
    if (enabled == null || "false".equals(enabled)) return null;
    if (!"true".equals(enabled) || !"FIVE_ACTORS".equals(System.getenv("TASK_IDENTITY_MODEL")))
      throw new IllegalStateException("Invalid claimed session configuration");
    String realm = required("ORISO_ACCOUNT_LIFECYCLE_REALM"), creator = required("IDENTITY_ACCOUNT_CREATE_SERVICE_SUBJECT"),
        admin = required("IDENTITY_ACCOUNT_ADMIN_SERVICE_SUBJECT"), encoded = required("ORISO_TASK_CONTEXT_KEY");
    if (creator.equals(admin)) throw new IllegalStateException("Distinct session actors required");
    byte[] key;
    try { key = Base64.getDecoder().decode(encoded); }
    catch (IllegalArgumentException failure) { throw new IllegalStateException("Invalid session key"); }
    if (key.length < 32) throw new IllegalStateException("Invalid session key length");
    var mappings = parse(required("ORISO_ACCOUNT_LIFECYCLE_GROUPS"));
    var allowed = new TreeMap<String,Set<String>>();
    mappings.fields().forEachRemaining(entry -> {
      if (!entry.getKey().matches("/human-roles/[a-z0-9-]{1,80}") || !entry.getValue().isArray()
          || entry.getValue().isEmpty() || entry.getValue().size() > 5) bad();
      var roles = new HashSet<String>();
      entry.getValue().forEach(role -> {
        if (!role.isTextual() || !LifecycleGroups.KNOWN.contains(role.asText()) || !roles.add(role.asText())) bad();
      });
      if (LifecycleGroups.allowedKind(roles) == null) bad();
      allowed.put(entry.getKey(),Set.copyOf(roles));
    });
    if (allowed.isEmpty()) throw new IllegalStateException("Ordinary session profiles required");
    return new MagicLinkAuthority(new LifecycleAuthorization(realm,creator,admin,key,encoded),allowed);
  }
  private static String required(String name) {
    String value = System.getenv(name);
    if (value == null || value.isBlank() || value.contains("${"))
      throw new IllegalStateException("Missing claimed session configuration");
    return value;
  }
  static boolean present(AuthenticationFlowContext context) {
    return context.getHttpRequest().getDecodedFormParameters().containsKey(MagicLinkAuthenticator.COMMAND);
  }
  record Checked(JsonNode command, String workflow, String target, String digest, long expiry, UserModel user, String ownerClient, String ownerSubject) {}
  Checked check(AuthenticationFlowContext context) {
    var session = context.getSession();
    var realm = context.getRealm();
    var form = context.getHttpRequest().getDecodedFormParameters();
    if (!"app".equals(form.getFirst("client_id")) || !"password".equals(form.getFirst("grant_type"))
        || !Set.of("client_id","grant_type",MagicLinkAuthenticator.COMMAND,"scope","otp","totp").containsAll(form.keySet())
        || form.values().stream().anyMatch(values -> values == null || values.size()!=1)
        || form.containsKey("scope") && !"openid".equals(form.getFirst("scope"))) deny();
    var commands = form.get(MagicLinkAuthenticator.COMMAND);
    if (commands == null || commands.size() != 1 || form.containsKey("username") || form.containsKey("password")
        || form.containsKey("requested_subject") || form.containsKey("subject_token")) deny();
    var command = parse(commands.get(0));
    fields(command,"version","workflowId","targetUserId","tenantId","clientId","expiresAt","claimDigest");
    String workflow = uuid(text(command,"workflowId",36,false)), target = uuid(text(command,"targetUserId",36,false));
    long tenant = number(command,"tenantId",true), expiry = number(command,"expiresAt",true), now = Instant.now().getEpochSecond();
    if (number(command,"version",true) != 1 || !"app".equals(text(command,"clientId",255,false))
        || expiry <= now || expiry-now > 900) deny();
    hex(text(command,"claimDigest",64,false));
    var client = context.getAuthenticationSession().getClient();
    if (client == null || !"app".equals(client.getClientId()) || !client.isEnabled() || !client.isPublicClient()
        || !client.isDirectAccessGrantsEnabled() || !client.isStandardFlowEnabled() || client.isServiceAccountsEnabled()
        || !"openid-connect".equals(client.getProtocol()) || !realm.isEnabled() || !auth.realmName.equals(realm.getName())) deny();
    String proof = context.getHttpRequest().getHttpHeaders().getHeaderString("X-ORISO-Task-Context");
    // Cryptographic preflight precedes all owned target/replay locks.
    var machine = auth.requireMachine(session,"ACCOUNT_ADMIN");
    auth.verifyMagicLinkCommand(proof,machine,"realm/"+realm.getId()+"/magic-link/"+workflow,command);
    session.getContext().setClient(client);
    var em = CurrentNativeHumanIdentity.entityManager(session);
    var currentRealm = NativeCurrentGrants.one(em,"select NAME, ENABLED from REALM where ID = :id for update",realm.getId());
    if (!auth.realmName.equals(NativeCurrentGrants.text(currentRealm[0])) || !NativeCurrentGrants.flag(currentRealm[1])) deny();
    CurrentNativeHumanIdentity.currentClient(em,realm.getId(),client.getId(),"app",null);
    var nativeClient = NativeCurrentGrants.one(em,"select PUBLIC_CLIENT, DIRECT_ACCESS_GRANTS_ENABLED from CLIENT where ID = :id for update",client.getId());
    if (!NativeCurrentGrants.flag(nativeClient[0]) || !NativeCurrentGrants.flag(nativeClient[1])) deny();
    var current = AccountLifecycleResource.lockedSnapshot(em,target);
    if (!realm.getId().equals(current.path("realmId").asText()) || !current.path("enabled").asBoolean()
        || !current.path("serviceAccountClientLink").isNull() || !current.path("federationLink").isNull()) deny();
    var tenants = current.path("attributes").path("tenantId");
    if (!tenants.isArray() || tenants.size() != 1 || !tenants.get(0).isTextual()
        || !Long.toString(tenant).equals(tenants.get(0).asText())) deny();
    var roleIds = new TreeSet<String>(); current.path("roles").forEach(value -> roleIds.add(value.asText()));
    var groupIds = new TreeSet<String>(); current.path("groups").forEach(value -> groupIds.add(value.asText()));
    if (groupIds.size() != 1) deny();
    var grants = NativeCurrentGrants.read(em,realm.getId(),roleIds,groupIds);
    String path = grants.paths().get(groupIds.first());
    if (!grants.clientRoles().isEmpty() || grants.groups().size() != 2 || !groups.containsKey(path)
        || !groups.get(path).equals(grants.realmRoles())
        || !grants.paths().containsValue("/human-roles")) deny();
    // Cached/native bearer authentication is repeated while the exact current target is locked.
    auth.requireMachine(session,"ACCOUNT_ADMIN");
    session.getContext().setClient(client);
    var user = session.users().getUserById(realm,target);
    if (user == null || !user.isEnabled() || user.getServiceAccountClientLink() != null || user.getFederationLink() != null
        || !current.path("username").asText().equals(user.getUsername())) deny();
    return new Checked(command,workflow,target,auth.mac("magic-link-command/v1",command),expiry,user,machine.clientId(),machine.subject());
  }
  void recheckMachine(AuthenticationFlowContext context, Checked checked) {
    var client = context.getAuthenticationSession().getClient();
    var machine = auth.requireMachine(context.getSession(),"ACCOUNT_ADMIN");
    auth.verifyMagicLinkCommand(context.getHttpRequest().getHttpHeaders().getHeaderString("X-ORISO-Task-Context"),
        machine,"realm/"+context.getRealm().getId()+"/magic-link/"+checked.workflow(),checked.command());
    context.getSession().getContext().setClient(client);
  }
}
