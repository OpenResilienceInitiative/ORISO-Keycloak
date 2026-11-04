package org.oriso.keycloak.lifecycle;

import java.util.*;
import org.keycloak.Config;
import org.keycloak.models.*;
import org.keycloak.services.resource.*;

/** Standalone provider; absent/false enable flag does not register a resource. */
public final class AccountLifecycleFactory implements RealmResourceProviderFactory {
  private LifecycleAuthorization authorization;
  private Map<String, Set<String>> groups;
  private static final java.util.logging.Logger LOG = java.util.logging.Logger.getLogger(AccountLifecycleFactory.class.getName());
  private GeneralPolicy humanPolicy;
  private InstallationStatus installation;
  private volatile GeneralPolicy readyHumanPolicy;

  public void init(Config.Scope scope) {
    String enabled = System.getenv("ORISO_ACCOUNT_LIFECYCLE_ENABLED");
    if (enabled == null || "false".equals(enabled)) return;
    if (!"true".equals(enabled) || !"FIVE_ACTORS".equals(System.getenv("TASK_IDENTITY_MODEL")))
      throw new IllegalStateException("Invalid lifecycle enable/model configuration");
    String realm = required("ORISO_ACCOUNT_LIFECYCLE_REALM");
    String creator = required("IDENTITY_ACCOUNT_CREATE_SERVICE_SUBJECT");
    String admin = required("IDENTITY_ACCOUNT_ADMIN_SERVICE_SUBJECT");
    if (creator.equals(admin))
      throw new IllegalStateException("Lifecycle actor subjects must differ");
    String encoded = required("ORISO_TASK_CONTEXT_KEY");
    byte[] key;
    try {
      key = Base64.getDecoder().decode(encoded);
    } catch (IllegalArgumentException failure) {
      throw new IllegalStateException("Lifecycle key must be base64");
    }
    if (key.length < 32)
      throw new IllegalStateException("Lifecycle key must contain at least 32 bytes");
    groups = new LinkedHashMap<>();
    var config = LifecycleJson.parse(required("ORISO_ACCOUNT_LIFECYCLE_GROUPS"));
    config
        .fields()
        .forEachRemaining(
            entry -> {
              if (!entry.getKey().matches("/human-roles/[a-z0-9-]{1,80}")
                  || !entry.getValue().isArray()
                  || entry.getValue().isEmpty()
                  || entry.getValue().size() > 5)
                throw new IllegalStateException("Invalid ordinary lifecycle mapping");
              Set<String> roles = new HashSet<>();
              entry
                  .getValue()
                  .forEach(
                      role -> {
                        if (!role.isTextual()
                            || !LifecycleGroups.KNOWN.contains(role.asText())
                            || !roles.add(role.asText()))
                          throw new IllegalStateException(
                              "Invalid ordinary lifecycle role mapping");
                      });
              if (LifecycleGroups.allowedKind(roles) == null)
                throw new IllegalStateException("Unknown ordinary lifecycle combination");
              groups.put(entry.getKey(), Set.copyOf(roles));
            });
    if (groups.isEmpty()) throw new IllegalStateException("Missing ordinary lifecycle mappings");
    authorization = new LifecycleAuthorization(realm, creator, admin, key, encoded);
    String humanConfig = System.getenv("ORISO_ACCOUNT_MAINTENANCE_CONFIG");
    if (humanConfig != null) humanPolicy = new GeneralPolicy(LifecycleJson.parse(humanConfig));
    installation = new InstallationStatus(System::getenv, config);
  }

  private static String required(String name) {
    String value = System.getenv(name);
    if (value == null || value.isBlank() || value.contains("${"))
      throw new IllegalStateException("Missing lifecycle configuration: " + name);
    return value;
  }

  public RealmResourceProvider create(KeycloakSession session) {
    return authorization == null
        ? null
        : new AccountLifecycleResource(session, authorization, groups,
            () -> installation.read(session, authorization, checkedHumanPolicy(session)));
  }

  // Both finite providers share exactly the same trusted configuration parser.
  RealmResourceProvider createMaintenance(KeycloakSession session) {
    return authorization == null
        ? null
        : new AccountMaintenanceResource(session, authorization, groups, () -> checkedHumanPolicy(session), humanPolicy);
  }

  public String getId() {
    return "oriso-account-lifecycle";
  }

  public void postInit(KeycloakSessionFactory factory) {
    if (humanPolicy == null) return;
    factory.register(event -> {
      if (!(event instanceof org.keycloak.models.utils.PostMigrationEvent)) return;
      readyHumanPolicy = null;
      var committed = new java.util.concurrent.atomic.AtomicBoolean();
      try {
        org.keycloak.models.utils.KeycloakModelUtils.runJobInTransaction(factory, session -> {
          session.getTransactionManager().enlistAfterCompletion(new AbstractKeycloakTransaction() {
            protected void commitImpl() { committed.set(true); }
            protected void rollbackImpl() { committed.set(false); }
          });
          var realm = session.realms().getRealm(humanPolicy.nativePolicy.realmId);
          if (realm == null) throw new IllegalStateException("Ordinary human native realm is missing");
          session.getContext().setRealm(realm);
          humanPolicy.validateInstallation(session);
        });
      } catch (RuntimeException unavailable) {
        LOG.warning("Ordinary human operations unavailable: native binding validation failed");
        return;
      }
      if (committed.get()) readyHumanPolicy = humanPolicy;
    });
  }

  static GeneralPolicy checkedOrdinaryPolicy(KeycloakSession session) {
    var factory=session.getKeycloakSessionFactory().getProviderFactory(RealmResourceProvider.class,"oriso-account-lifecycle");
    if(!(factory instanceof AccountLifecycleFactory))LifecycleJson.deny();
    return ((AccountLifecycleFactory)factory).checkedHumanPolicy(session);
  }

  static OrdinaryAdminSource checkedOrdinarySource(KeycloakSession session,LifecycleAuthorization crypto,MaintenanceRequest request,String header){
    return checkedOrdinarySource(session,crypto,request.target().path("origin"),request.target().path("tenantId"),header);
  }

  static OrdinaryAdminSource checkedOrdinarySource(KeycloakSession session,LifecycleAuthorization crypto,
      com.fasterxml.jackson.databind.JsonNode origin,com.fasterxml.jackson.databind.JsonNode tenant,String header){
    var factory=session.getKeycloakSessionFactory().getProviderFactory(RealmResourceProvider.class,"oriso-account-lifecycle");
    if(!(factory instanceof AccountLifecycleFactory))LifecycleJson.deny();var actual=(AccountLifecycleFactory)factory;
    return OrdinaryAdminSource.require(session,crypto,actual.checkedHumanPolicy(session),actual.groups,origin,tenant,header);
  }

  static boolean transferredPlatformSelf(KeycloakSession session,MaintenanceRequest request){
    var factory=session.getKeycloakSessionFactory().getProviderFactory(RealmResourceProvider.class,"oriso-account-lifecycle");
    if(!(factory instanceof AccountLifecycleFactory))LifecycleJson.deny();
    var actual=(AccountLifecycleFactory)factory;
    if(actual.authorization==null)LifecycleJson.deny();
    var transfer=ProtectedOrdinaryTransfer.require(session,actual.authorization,request.accountId());
    return transfer.originalPlatform()&&"0".equals(transfer.lineage().tenant().asText())
        &&"CONSULTANT".equals(LifecycleGroups.allowedKind(HumanPolicyJson.strings(transfer.lineage().nativeProfile().path("realmRoles"),1,10,255)));
  }

  private GeneralPolicy checkedHumanPolicy(KeycloakSession session) {
    if (humanPolicy == null) throw new jakarta.ws.rs.ForbiddenException();
    var ready = readyHumanPolicy;
    if (ready == null) {
      session.getContext().getHttpResponse().setHeader("Cache-Control", "no-store");
      throw new jakarta.ws.rs.ServiceUnavailableException(jakarta.ws.rs.core.Response.status(503)
          .header("Cache-Control", "no-store").build());
    }
    return ready;
  }

  jakarta.ws.rs.core.Response readOtpSelf(KeycloakSession session, String username,
      String targetHeader, String proofHeader, String humanHeader,
      java.util.function.Function<ScopedOtpAccess.VerifiedOtpTarget, jakarta.ws.rs.core.Response> read) {
    if (authorization == null) LifecycleJson.deny();
    return ScopedOtpAccess.checkedSelfRead(session, authorization, groups, this::checkedHumanPolicy,
        username, targetHeader, proofHeader, humanHeader, read);
  }

  jakarta.ws.rs.core.Response appSetupOtpProtected(KeycloakSession session, String username,
      byte[] raw, String proofHeader, String humanHeader, String bootstrapReceipt,
      java.util.function.Function<ScopedOtpAccess.VerifiedOtpTarget, jakarta.ws.rs.core.Response> setup) {
    if (authorization == null) LifecycleJson.deny();
    return ScopedOtpAccess.checkedProtectedApp(session, authorization, username, raw, proofHeader,
        humanHeader, bootstrapReceipt, setup);
  }

  jakarta.ws.rs.core.Response appSetupOtpSelf(KeycloakSession session, String username,
      byte[] raw, String proofHeader, String humanHeader,
      java.util.function.Function<ScopedOtpAccess.VerifiedOtpTarget, jakarta.ws.rs.core.Response> setup) {
    if (authorization == null) LifecycleJson.deny();
    return ScopedOtpAccess.checkedSelfMutation(session, authorization, groups, this::checkedHumanPolicy,
        "otp.app-setup", "PUT", username, raw, proofHeader, humanHeader, setup);
  }

  jakarta.ws.rs.core.Response deleteOtpSelf(KeycloakSession session, String username,
      byte[] raw, String proofHeader, String humanHeader,
      java.util.function.Function<ScopedOtpAccess.VerifiedOtpTarget, jakarta.ws.rs.core.Response> delete) {
    if (authorization == null) LifecycleJson.deny();
    return ScopedOtpAccess.checkedSelfMutation(session, authorization, groups, this::checkedHumanPolicy,
        "otp.delete", "DELETE", username, raw, proofHeader, humanHeader, delete);
  }

  jakarta.ws.rs.core.Response finishEmailOtpSelf(KeycloakSession session, String username,
      byte[] raw, String proofHeader, String humanHeader,
      java.util.function.Function<ScopedOtpAccess.VerifiedOtpTarget, jakarta.ws.rs.core.Response> finish) {
    if (authorization == null) LifecycleJson.deny();
    return ScopedOtpAccess.checkedSelfMutation(session, authorization, groups, this::checkedHumanPolicy,
        "otp.email-finish", "POST", username, raw, proofHeader, humanHeader, finish);
  }

  jakarta.ws.rs.core.Response startEmailOtpSelf(KeycloakSession session, String username,
      byte[] raw, String proofHeader, String humanHeader,
      java.util.function.Function<ScopedOtpAccess.VerifiedOtpTarget, jakarta.ws.rs.core.Response> prepare,
      java.util.function.Function<ScopedOtpAccess.VerifiedOtpTarget, jakarta.ws.rs.core.Response> send) {
    if (authorization == null) LifecycleJson.deny();
    return ScopedOtpAccess.checkedSelfEmailStart(session, authorization, groups, this::checkedHumanPolicy,
        username, raw, proofHeader, humanHeader, prepare, send);
  }

  jakarta.ws.rs.core.Response startEmailOtpProtected(KeycloakSession session, String username,
      byte[] raw, String proofHeader, String humanHeader, String bootstrapReceipt,
      java.util.function.Function<ScopedOtpAccess.VerifiedOtpTarget, jakarta.ws.rs.core.Response> prepare,
      java.util.function.Function<ScopedOtpAccess.VerifiedOtpTarget, jakarta.ws.rs.core.Response> send) {
    if (authorization == null) LifecycleJson.deny();
    return ProtectedOtpBootstrap.emailStart(session, authorization, username, raw, proofHeader,
        humanHeader, bootstrapReceipt, prepare, send);
  }

  jakarta.ws.rs.core.Response finishEmailOtpProtected(KeycloakSession session, String username,
      byte[] raw, String proofHeader, String humanHeader, String bootstrapReceipt,
      java.util.function.Function<ScopedOtpAccess.VerifiedOtpTarget, jakarta.ws.rs.core.Response> finish) {
    if (authorization == null) LifecycleJson.deny();
    return ProtectedOtpBootstrap.emailFinish(session, authorization, username, raw, proofHeader,
        humanHeader, bootstrapReceipt, finish);
  }

  public void close() {}
}
