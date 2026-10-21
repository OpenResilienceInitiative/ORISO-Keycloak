package org.oriso.keycloak.lifecycle.proof;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import java.net.HttpURLConnection;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import java.util.stream.Stream;
import org.keycloak.Config;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.AbstractKeycloakTransaction;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.utils.PostMigrationEvent;
import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderEvent;
import org.keycloak.provider.ProviderEventListener;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.provider.Spi;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;
import org.oriso.keycloak.lifecycle.ProtectedInvitationFactory;

/** Disposable proof JAR only. No principal, model or operation authority is synthesized. */
public final class ReadinessRollbackFixtureFactory implements RealmResourceProviderFactory {
  private static final String VALIDATION_FAILURE =
      "Protected invitation provider unavailable: native binding validation failed";
  private final AtomicBoolean workerStarted = new AtomicBoolean();
  private volatile boolean enabled, nativeProbe, captured, sessionCreated, rollbackOnly;
  private volatile boolean began, rolledBack, committed, returned, warningsAbsent, complete, failed;
  private volatile String stage = "INERT";
  private Thread worker;
  private String realmName;

  public void init(Config.Scope ignored) {
    String flag = System.getenv("ORISO_PROOF_READINESS_ROLLBACK_ONLY");
    if (flag == null || "false".equals(flag)) return;
    if (!"true".equals(flag)) throw new IllegalStateException("Invalid proof fixture flag");
    try {
      realmName = new ObjectMapper().readTree(System.getenv("ORISO_PROTECTED_INVITATIONS_CONFIG"))
          .path("realmName").textValue();
      if (realmName == null || !realmName.matches("[A-Za-z0-9._-]{1,255}"))
        throw new IllegalStateException("Invalid proof realm");
    } catch (java.io.IOException failure) {
      throw new IllegalStateException("Invalid proof configuration");
    }
    enabled = true;
  }

  public void postInit(KeycloakSessionFactory factory) {
    if (!enabled) return;
    factory.register(event -> {
      if (event instanceof PostMigrationEvent && workerStarted.compareAndSet(false, true)) {
        worker = new Thread(() -> exercise(factory), "oriso-proof-readiness-rollback");
        worker.setDaemon(true);
        worker.start();
      }
    });
  }

  private void exercise(KeycloakSessionFactory actual) {
    try {
      stage = "WAITING_NATIVE_AUTH_PROBE";
      long deadline = System.nanoTime() + 60_000_000_000L;
      URI probe = URI.create("http://127.0.0.1:8080/realms/" + realmName
          + "/oriso-protected-invitations/v1/approvals/" + UUID.randomUUID());
      while (System.nanoTime() < deadline && !Thread.currentThread().isInterrupted()) {
        int status = unauthenticatedProbe(probe);
        if (status == 401 || status == 403) { nativeProbe = true; break; }
        Thread.sleep(200);
      }
      if (!nativeProbe) { stage = "NATIVE_AUTH_PROBE_UNAVAILABLE"; failed = true; return; }
      var installed = actual.getProviderFactory(RealmResourceProvider.class, "oriso-protected-invitations");
      if (!(installed instanceof ProtectedInvitationFactory protectedFactory))
        throw new IllegalStateException("Unexpected proof provider");
      var adapter = new ValidationFactory(actual);
      protectedFactory.postInit(adapter);
      if (adapter.listener == null) throw new IllegalStateException("Missing captured listener");
      captured = true;
      Logger logger = Logger.getLogger(ProtectedInvitationFactory.class.getName());
      if (logger.getFilter() != null || !logger.isLoggable(Level.WARNING))
        throw new IllegalStateException("Proof warning observation unavailable");
      AtomicInteger warnings = new AtomicInteger();
      Handler observer = new Handler() {
        public void publish(LogRecord record) {
          if (ProtectedInvitationFactory.class.getName().equals(record.getLoggerName())
              && VALIDATION_FAILURE.equals(record.getMessage())) warnings.incrementAndGet();
        }
        public void flush() {}
        public void close() {}
      };
      observer.setLevel(Level.ALL);
      stage = "RUNNING_REAL_NATIVE_VALIDATION";
      logger.addHandler(observer);
      try {
        adapter.listener.onEvent(new PostMigrationEvent(actual));
        returned = true;
      } finally {
        logger.removeHandler(observer);
      }
      warningsAbsent = warnings.get() == 0;
      if (!sessionCreated || !rollbackOnly || !began || !rolledBack || committed || !warningsAbsent)
        throw new IllegalStateException("Actual rollback preconditions not proved");
      stage = "COMPLETE";
    } catch (InterruptedException interrupted) {
      Thread.currentThread().interrupt();
      stage = "WORKER_INTERRUPTED";
      failed = true;
    } catch (RuntimeException failure) {
      stage = "WORKER_FAILED";
      failed = true;
    } finally {
      complete = true;
    }
  }

  private static int unauthenticatedProbe(URI uri) {
    HttpURLConnection connection = null;
    try {
      connection = (HttpURLConnection) uri.toURL().openConnection();
      connection.setConnectTimeout(1000);
      connection.setReadTimeout(1000);
      connection.setRequestMethod("PUT");
      connection.setRequestProperty("Content-Type", "application/json");
      connection.setDoOutput(true);
      try (var output = connection.getOutputStream()) {
        output.write("{\"scope\":{}}".getBytes(StandardCharsets.UTF_8));
      }
      return connection.getResponseCode();
    } catch (java.io.IOException unavailable) {
      return -1;
    } finally {
      if (connection != null) connection.disconnect();
    }
  }

  /** Only these two public factory operations are supported by the proof adapter. */
  private final class ValidationFactory implements KeycloakSessionFactory {
    private final KeycloakSessionFactory actual;
    private ProviderEventListener listener;
    private ValidationFactory(KeycloakSessionFactory actual) { this.actual = actual; }
    public void register(ProviderEventListener value) {
      if (value == null || listener != null) throw unsupported();
      listener = value;
    }
    public KeycloakSession create() {
      if (sessionCreated) throw unsupported();
      var nativeSession = actual.create();
      try {
        var tx = nativeSession.getTransactionManager();
        if (tx.isActive()) throw unsupported();
        tx.setRollbackOnly();
        rollbackOnly = tx.getRollbackOnly();
        tx.enlistAfterCompletion(new AbstractKeycloakTransaction() {
          protected void beginImpl() { began = true; }
          protected void commitImpl() { committed = true; }
          protected void rollbackImpl() { rolledBack = true; }
        });
        sessionCreated = true;
        return nativeSession;
      } catch (RuntimeException failure) {
        nativeSession.close();
        throw failure;
      }
    }
    public Set<Spi> getSpis() { throw unsupported(); }
    public Spi getSpi(Class<? extends Provider> type) { throw unsupported(); }
    public <T extends Provider> ProviderFactory<T> getProviderFactory(Class<T> type) { throw unsupported(); }
    public <T extends Provider> ProviderFactory<T> getProviderFactory(Class<T> type, String id) { throw unsupported(); }
    public <T extends Provider> ProviderFactory<T> getProviderFactory(Class<T> type, String realm, String component,
        Function<KeycloakSessionFactory, ComponentModel> getter) { throw unsupported(); }
    public Stream<ProviderFactory> getProviderFactoriesStream(Class<? extends Provider> type) { throw unsupported(); }
    public long getServerStartupTimestamp() { throw unsupported(); }
    public void close() { throw unsupported(); }
    public void unregister(ProviderEventListener value) { throw unsupported(); }
    public void publish(ProviderEvent value) { throw unsupported(); }
    public void invalidate(KeycloakSession session, InvalidableObjectType type, Object... parameters) { throw unsupported(); }
  }

  private static UnsupportedOperationException unsupported() {
    return new UnsupportedOperationException("Unsupported proof factory operation");
  }

  private Map<String, Object> snapshot() {
    Map<String, Object> value = new TreeMap<>();
    value.put("enabled", enabled); value.put("workerStarted", workerStarted.get());
    value.put("nativeUnauthorizedProbeObserved", nativeProbe); value.put("capturedOneListener", captured);
    value.put("ownedSessionCreated", sessionCreated); value.put("rollbackOnlyBeforeBegin", rollbackOnly);
    value.put("observerBegan", began); value.put("observerRolledBack", rolledBack); value.put("observerCommitted", committed);
    value.put("callbackReturnedNormally", returned); value.put("validationWarningsAbsent", warningsAbsent);
    value.put("workerComplete", complete); value.put("workerFailed", failed); value.put("stage", stage);
    return value;
  }

  public RealmResourceProvider create(KeycloakSession ignored) {
    return new RealmResourceProvider() {
      public Object getResource() { return new StatusResource(); }
      public void close() {}
    };
  }

  public final class StatusResource {
    private StatusResource() {}
    @GET @Produces(MediaType.APPLICATION_JSON)
    public Map<String, Object> status() { return snapshot(); }
  }

  public String getId() { return "oriso-proof-readiness"; }
  public void close() {
    if (worker != null && worker.isAlive()) {
      worker.interrupt();
      try { worker.join(1000); }
      catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
    }
  }
}
