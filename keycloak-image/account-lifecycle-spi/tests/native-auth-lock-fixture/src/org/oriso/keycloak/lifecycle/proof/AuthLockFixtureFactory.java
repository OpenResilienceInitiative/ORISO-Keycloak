package org.oriso.keycloak.lifecycle.proof;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.persistence.LockModeType;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import org.keycloak.Config;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.models.AbstractKeycloakTransaction;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.jpa.entities.RealmEntity;
import org.keycloak.models.utils.PostMigrationEvent;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/** Separate disposable proof JAR. No resource, principal or operation capability is exposed. */
public final class AuthLockFixtureFactory implements RealmResourceProviderFactory {
  private static final Path CONTROL = Path.of("/opt/keycloak/proof-auth-lock");
  private static final String PREFIX = "ORISO_PROOF_AUTH_LOCK_V1 ";
  private final AtomicBoolean started = new AtomicBoolean();
  private String realmId, realmName;
  private Thread worker;
  private int caseCount = 9;

  public void init(Config.Scope ignored) {
    if (!"true".equals(System.getenv("ORISO_PROTECTED_INVITATIONS_ENABLED"))) return;
    String mode = System.getenv("ORISO_PROOF_AUTH_LOCK_CASE");
    if (mode != null) {
      if (!"CLEANUP_STATUS".equals(mode)) throw new IllegalStateException("Invalid fixed proof case");
      caseCount = 1;
    }
    try {
      var config = new ObjectMapper().readTree(System.getenv("ORISO_PROTECTED_INVITATIONS_CONFIG"));
      realmId = config.path("realmId").textValue();
      realmName = config.path("realmName").textValue();
      if (realmId == null || realmName == null || !realmId.equals(java.util.UUID.fromString(realmId).toString())
          || !realmName.matches("[A-Za-z0-9._-]{1,255}")) throw new IllegalStateException("Invalid proof config");
    } catch (java.io.IOException failure) { throw new IllegalStateException("Invalid proof config"); }
  }

  public void postInit(KeycloakSessionFactory factory) {
    factory.register(event -> {
      if (!(event instanceof PostMigrationEvent) || !started.compareAndSet(false, true)) return;
      emit(-1, realmId == null ? "INERT" : "ARMED", false, false, false, false, false);
      if (realmId == null) return;
      worker = new Thread(() -> exercise(factory), "oriso-proof-auth-lock");
      worker.setDaemon(true);
      worker.start();
    });
  }

  private void exercise(KeycloakSessionFactory factory) {
    try {
      long deadline = System.nanoTime() + 240_000_000_000L;
      for (int index = 0; index < caseCount; index++) {
        while (!Files.isRegularFile(CONTROL.resolve(index + ".arm"))) {
          if (System.nanoTime() >= deadline) throw new IllegalStateException("Proof arm deadline");
          Thread.sleep(25);
        }
        hold(factory, index);
      }
      emit(caseCount, "COMPLETE", true, true, false, true, false);
    } catch (InterruptedException interrupted) {
      Thread.currentThread().interrupt();
      emit(-1, "FAILED", false, false, false, false, true);
    } catch (RuntimeException failure) {
      emit(-1, "FAILED", false, false, false, false, true);
    }
  }

  private void hold(KeycloakSessionFactory factory, int index) throws InterruptedException {
    boolean[] completion = new boolean[3];
    boolean pinned = false, owned = false, held = false, blocked = false;
    var selector = emptySelector();
    try (var session = factory.create()) {
      var tx = session.getTransactionManager();
      if (tx.isActive()) throw new IllegalStateException("Unexpected active proof transaction");
      tx.enlistAfterCompletion(new AbstractKeycloakTransaction() {
        protected void beginImpl() { completion[0] = true; }
        protected void commitImpl() { completion[1] = true; }
        protected void rollbackImpl() { completion[2] = true; }
      });
      tx.begin();
      try {
        var em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        pinned = "2.4.240".equals(em.createNativeQuery("select H2VERSION()").getSingleResult().toString());
        if (!pinned) throw new IllegalStateException("Unexpected runtime H2 version");
        long holder = ((Number) em.createNativeQuery("select SESSION_ID()").getSingleResult()).longValue();
        var realm = em.find(RealmEntity.class, realmId, LockModeType.PESSIMISTIC_WRITE);
        owned = tx.isActive() && em.isJoinedToTransaction() && completion[0];
        held = realm != null && realmId.equals(realm.getId()) && realmName.equals(realm.getName());
        if (!owned || !held) throw new IllegalStateException("Actual native realm lock required");
        emit(index, "LOCKED", pinned, owned, held, false, false, selector);
        long deadline = System.nanoTime() + 5_000_000_000L;
        while (!Files.isRegularFile(CONTROL.resolve(index + ".release"))) {
          if (System.nanoTime() >= deadline) throw new IllegalStateException("Proof lock deadline");
          var rows = em.createNativeQuery("select SESSION_ID, SESSION_STATE, BLOCKER_ID, EXECUTING_STATEMENT"
              + " from INFORMATION_SCHEMA.SESSIONS where BLOCKER_ID = :holder")
              .setParameter("holder", holder).getResultList();
          selector.put("holderWaiterObserved", selector.get("holderWaiterObserved") || !rows.isEmpty());
          for (Object raw : rows) {
            var row = (Object[]) raw;
            String sql = row[3] == null ? "" : row[3].toString().toLowerCase(java.util.Locale.ROOT)
                .replace('"', ' ').replaceAll("\\s+", " ").trim();
            selector.put("distinctSessionObserved", selector.get("distinctSessionObserved") || ((Number) row[0]).longValue() != holder);
            selector.put("blockedStateObserved", selector.get("blockedStateObserved") || "BLOCKED".equals(row[1]));
            selector.put("realmTableObserved", selector.get("realmTableObserved") || sql.matches(".* from (public\\.)?realm\\b.*"));
            selector.put("idPredicateObserved", selector.get("idPredicateObserved") || sql.matches(".* where ([a-z0-9_]+\\.)?id\\s*=\\s*\\?.*"));
            selector.put("forUpdateObserved", selector.get("forUpdateObserved") || sql.contains(" for update"));
            selector.put("exactBoundRealmParameterObserved", selector.get("exactBoundRealmParameterObserved") || sql.endsWith(" {1: '" + realmId + "'}"));
            // SQL and session identifiers are examined only in this native worker's memory.
            // H2 Command.toString appends Trace.formatParams. Require that one
            // exact parameter to be this holder's actual canonical realm UUID.
            boolean exactRealmQuery = sql.matches("select .+ from (public\\.)?realm [a-z0-9_]+ where [a-z0-9_]+\\.id=\\? for update \\{1: '"
                + java.util.regex.Pattern.quote(realmId) + "'\\}");
            if (((Number) row[0]).longValue() != holder && "BLOCKED".equals(row[1])
                && row[2] instanceof Number n && n.longValue() == holder && exactRealmQuery && !blocked) {
              blocked = true;
              emit(index, "BLOCKED", pinned, owned, held, true, false, selector);
            }
          }
          Thread.sleep(25);
        }
      } finally {
        if (tx.isActive()) tx.rollback();
      }
      if (!completion[0] || completion[1] || !completion[2] || tx.isActive())
        throw new IllegalStateException("Actual proof rollback required");
      emit(index, "RELEASED", pinned, owned, held, blocked, false, selector);
    }
  }

  private static Map<String, Boolean> emptySelector() {
    return new java.util.TreeMap<>(Map.of("holderWaiterObserved", false, "distinctSessionObserved", false,
        "blockedStateObserved", false, "realmTableObserved", false, "idPredicateObserved", false,
        "forUpdateObserved", false, "exactBoundRealmParameterObserved", false));
  }

  private static void emit(int index, String phase, boolean pinned, boolean owned,
      boolean held, boolean blocked, boolean failed) {
    emit(index, phase, pinned, owned, held, blocked, failed, emptySelector());
  }

  private static void emit(int index, String phase, boolean pinned, boolean owned,
      boolean held, boolean blocked, boolean failed, Map<String, Boolean> selector) {
    try {
      System.out.println(PREFIX + new ObjectMapper().writeValueAsString(Map.of(
          "schema", 1, "index", index, "phase", phase, "runtimeH2Pinned", pinned,
          "nativeTransactionOwned", owned, "actualRealmRowHeld", held,
          "matchingBlockedRequest", blocked, "workerFailed", failed, "selectorObservation", selector)));
    } catch (com.fasterxml.jackson.core.JsonProcessingException failure) {
      throw new IllegalStateException("Proof observation unavailable");
    }
  }

  public RealmResourceProvider create(org.keycloak.models.KeycloakSession ignored) { return null; }
  public String getId() { return "oriso-proof-auth-lock"; }
  public void close() {
    if (worker != null && worker.isAlive()) {
      worker.interrupt();
      try { worker.join(1000); }
      catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
    }
  }
}
