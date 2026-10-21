package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;

import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;
import org.keycloak.models.AbstractKeycloakTransaction;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakTransactionManager;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.services.resource.RealmResourceProvider;

/** One provided boundary for the original OTP route. Assertions never construct a grant. */
public final class ScopedOtpAccess {
  private ScopedOtpAccess() {}

  public static Response requireSelfRead(KeycloakSession session, String exactPathUsername,
      String accountTargetHeader, String taskContextHeader, String fullImmediateHumanHeader,
      Function<VerifiedOtpTarget, Response> read) {
    try {
      var factory = session.getKeycloakSessionFactory().getProviderFactory(
          RealmResourceProvider.class, "oriso-account-lifecycle");
      if (!(factory instanceof AccountLifecycleFactory configuration)) deny();
      return ((AccountLifecycleFactory) factory).readOtpSelf(session, exactPathUsername,
          accountTargetHeader, taskContextHeader, fullImmediateHumanHeader, read);
    } catch (WebApplicationException rejected) {
      if (session.getTransactionManager().isActive()) session.getTransactionManager().setRollbackOnly();
      throw new WebApplicationException(Response.status(rejected.getResponse().getStatus())
          .type(MediaType.APPLICATION_JSON).entity(Map.of("error", "OTP request rejected"))
          .header("Cache-Control", "no-store").build());
    } catch (RuntimeException unavailable) {
      if (session.getTransactionManager().isActive()) session.getTransactionManager().setRollbackOnly();
      // Native exceptions can contain credentials or token data. Do not propagate their text/cause.
      throw new WebApplicationException(Response.status(503).type(MediaType.APPLICATION_JSON)
          .entity(Map.of("error", "OTP request could not complete"))
          .header("Cache-Control", "no-store").build());
    }
  }

  static Response checkedSelfRead(KeycloakSession session, LifecycleAuthorization authorization,
      Map<String, Set<String>> mappings, GeneralPolicy policy, String username,
      String targetHeader, String proofHeader, String humanHeader,
      Function<VerifiedOtpTarget, Response> read) {
    // Cache the canonical machine before native human authentication changes ambient context.
    var machine = authorization.requireMachine(session, "ACCOUNT_ADMIN");
    if (targetHeader == null || targetHeader.length() > 8192 || username == null
        || username.isBlank() || username.length() > 255
        || username.chars().anyMatch(c -> c < 32 || c == 127)) bad();
    var target = parse(targetHeader);
    String account = uuid(text(target, "accountId", 36, false));
    var materialized = JSON.createObjectNode();
    materialized.set("target", target);
    materialized.put("username", username);
    materialized.putNull("otp");
    var realm = session.getContext().getRealm();
    authorization.verifyCommand(proofHeader, machine, "oriso-otp", "OTP", "otp.read", "GET",
        "realm/" + realm.getId() + "/account/" + account, materialized);
    var body = JSON.createObjectNode();
    body.set("target", target);
    var request = MaintenanceRequest.parse("read", account, body);
    // Realm -> committed provenance -> current human -> native user/credential locks.
    var current = new MaintenanceTarget(session, authorization, mappings)
        .readOtpSelf(request, policy, humanHeader);
    if (!username.equals(current.path("username").textValue())) deny();
    var user = session.users().getUserById(realm, account);
    var cache = session.getProvider(org.keycloak.models.cache.UserCache.class);
    if (cache != null && user != null) {
      cache.evict(realm, user);
      user = session.users().getUserById(realm, account);
    }
    if (user == null || !username.equals(user.getUsername())) deny();
    var lifetime = new Lifetime(session);
    try {
      var checked = new VerifiedOtpTarget(lifetime, realm, user);
      var response = read.apply(checked);
      lifetime.check();
      if (response == null) throw new IllegalStateException("OTP callback did not return a response");
      return Response.fromResponse(response).header("Cache-Control", "no-store").build();
    } finally {
      lifetime.open = false;
    }
  }

  /** Same live request and transaction only. It contains no human bearer or transferable authority. */
  public static final class VerifiedOtpTarget {
    private final Lifetime lifetime;
    private final RealmModel realm;
    private final UserModel user;
    private VerifiedOtpTarget(Lifetime lifetime, RealmModel realm, UserModel user) {
      this.lifetime = lifetime;
      this.realm = realm;
      this.user = user;
    }
    public KeycloakSession session() { lifetime.check(); return lifetime.session; }
    public RealmModel realm() { lifetime.check(); return realm; }
    public UserModel user() { lifetime.check(); return user; }
    @Override public String toString() { return "VerifiedOtpTarget[redacted]"; }
  }

  private static final class Lifetime {
    private final KeycloakSession session;
    private final KeycloakTransactionManager transaction;
    private final Thread owner = Thread.currentThread();
    private volatile boolean open = true;
    private Lifetime(KeycloakSession session) {
      this.session = session;
      transaction = session.getTransactionManager();
      check();
      transaction.enlistAfterCompletion(new AbstractKeycloakTransaction() {
        protected void commitImpl() { open = false; }
        protected void rollbackImpl() { open = false; }
      });
    }
    private void check() {
      if (!open || Thread.currentThread() != owner || session.getTransactionManager() != transaction
          || !transaction.isActive() || transaction.getRollbackOnly()) deny();
    }
  }
}
