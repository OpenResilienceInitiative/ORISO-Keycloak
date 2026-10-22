package org.oriso.keycloak.lifecycle.proof;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import org.keycloak.Config;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailSenderProvider;
import org.keycloak.email.EmailSenderProviderFactory;
import org.keycloak.models.AbstractKeycloakTransaction;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.UserModel;

/** Disposable native SMTP observer. Always delegates the actual pinned default provider. */
public final class OtpWriterFixtureFactory implements EmailSenderProviderFactory {
  private static final Path CONTROL = Path.of("/opt/keycloak/proof-otp-writer/control.json");
  private static final String PREFIX = "ORISO_PROOF_OTP_WRITER_V1 ";
  public EmailSenderProvider create(KeycloakSession session) { return new Sender(session); }
  public void init(Config.Scope ignored) {}
  public void postInit(KeycloakSessionFactory ignored) {}
  public String getId() { return "oriso-proof-otp-writer"; }
  public void close() {}

  private static final class Sender implements EmailSenderProvider {
    private final KeycloakSession session;
    private final EmailSenderProvider delegate;
    Sender(KeycloakSession session) {
      this.session = session;
      delegateObservation("CONSTRUCTION_ENTERED", false, false);
      delegate = session.getProvider(EmailSenderProvider.class, "default");
      delegateObservation("CONSTRUCTED", delegate != null, delegate != null
          && "org.keycloak.email.DefaultEmailSenderProvider".equals(delegate.getClass().getName()));
      if (delegate == null || !"org.keycloak.email.DefaultEmailSenderProvider".equals(delegate.getClass().getName()))
        throw new IllegalStateException("Exact native SMTP delegate required");
    }
    public void validate(Map<String, String> config) throws EmailException {
      try {
        delegate.validate(config);
        delegateObservation("VALIDATED", true, true);
      } catch (EmailException | RuntimeException failure) {
        delegateObservation("VALIDATION_FAILED", true, true);
        throw failure;
      }
    }
    public void send(Map<String, String> config, String address, String subject, String text, String html)
        throws EmailException {
      if (Files.isRegularFile(CONTROL)) throw new EmailException("Proof requires actual native user");
      delegate.send(config, address, subject, text, html);
    }
    public void send(Map<String, String> config, UserModel user, String subject, String text, String html)
        throws EmailException {
      if (!Files.isRegularFile(CONTROL)) { delegate.send(config, user, subject, text, html); return; }
      var witness = capture(user);
      session.getTransactionManager().enlistAfterCompletion(new AbstractKeycloakTransaction() {
        protected void commitImpl() { witness.committed.set(true); emit("COMMITTED", witness); }
        protected void rollbackImpl() { emit("ROLLED_BACK", witness); }
      });
      var worker = new Thread(() -> observe(witness), "oriso-proof-otp-writer");
      worker.setDaemon(true); worker.start();
      try {
        delegate.send(config, user, subject, text, html);
        witness.sent.set(true); emit("SMTP_RETURNED", witness);
      } finally {
        witness.finished.set(true);
        try { worker.join(1000); }
        catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
      }
    }
    private Witness capture(UserModel user) {
      try {
        var control = new ObjectMapper().readTree(Files.readString(CONTROL));
        var names = new java.util.HashSet<String>(); control.fieldNames().forEachRemaining(names::add);
        if (!names.equals(Set.of("realmId", "accountId", "approvalId", "attemptId", "executionId", "operationId")))
          throw new IllegalStateException("Closed proof control required");
        for (String name : names) {
          var value = control.path(name);
          if (!value.isTextual() || !UUID.fromString(value.textValue()).toString().equals(value.textValue()))
            throw new IllegalStateException("Canonical proof target required");
        }
        String realm = control.path("realmId").textValue(), account = control.path("accountId").textValue();
        var em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        if (!session.getTransactionManager().isActive() || !em.isJoinedToTransaction()
            || !realm.equals(session.getContext().getRealm().getId()) || !account.equals(user.getId())
            || !"2.4.240".equals(em.createNativeQuery("select H2VERSION()").getSingleResult().toString()))
          throw new IllegalStateException("Actual pinned writer transaction required");
        var rows = em.createNativeQuery("select STATE from ORISO_OTP_EMAIL_DELIVERY where ID=:id and REALM_ID=:realm and ACCOUNT_ID=:account")
            .setParameter("id", realm + ":" + control.path("operationId").textValue())
            .setParameter("realm", realm).setParameter("account", account).getResultList();
        if (rows.size() != 1 || !"SENDING".equals(rows.get(0))) throw new IllegalStateException("Actual SENDING owner required");
        var bootstrap = em.createNativeQuery("select APPROVAL_ID, ATTEMPT_ID, EXECUTION_ID, STATE from ORISO_PROTECTED_OTP_BOOTSTRAP where REALM_ID=:realm and ACCOUNT_ID=:account")
            .setParameter("realm", realm).setParameter("account", account).getResultList();
        if (bootstrap.size() != 1) throw new IllegalStateException("Exact bootstrap owner required");
        var b = (Object[]) bootstrap.get(0);
        if (!control.path("approvalId").textValue().equals(b[0]) || !control.path("attemptId").textValue().equals(b[1])
            || !control.path("executionId").textValue().equals(b[2]) || !"EMAIL_READY".equals(b[3]))
          throw new IllegalStateException("Original bootstrap incarnation required");
        var attempts = em.createNativeQuery("select STATE, GENERATION, EXECUTION_ID from ORISO_ACCOUNT_LIFECYCLE_ATTEMPT where REALM_ID=:realm and ACCOUNT_ID=:account and ATTEMPT_ID=:attempt")
            .setParameter("realm", realm).setParameter("account", account)
            .setParameter("attempt", control.path("attemptId").textValue()).getResultList();
        if (attempts.size() != 1) throw new IllegalStateException("Exact pending attempt required");
        var a = (Object[]) attempts.get(0);
        if (!"OPEN".equals(a[0]) || !(a[1] instanceof Number n) || n.longValue() != 0
            || !control.path("executionId").textValue().equals(a[2])) throw new IllegalStateException("Original OPEN generation required");
        long connection = ((Number) em.createNativeQuery("select SESSION_ID()").getSingleResult()).longValue();
        if (connection < 1) throw new IllegalStateException("Actual writer session required");
        var witness = new Witness(session.getKeycloakSessionFactory(), realm, connection);
        emit("ENTERED", witness); return witness;
      } catch (java.io.IOException | RuntimeException failure) {
        throw new IllegalStateException("Native writer witness unavailable");
      }
    }
    public void close() {} // Session independently owns and closes the cached native delegate.
  }

  private static void delegateObservation(String phase, boolean present, boolean exact) {
    try {
      System.out.println("ORISO_PROOF_OTP_DELEGATE_V1 " + new ObjectMapper().writeValueAsString(
          Map.of("schema", 1, "phase", phase, "nativeDefaultPresent", present, "nativeDefaultClassExact", exact)));
    } catch (java.io.IOException unavailable) {
      throw new IllegalStateException("Native delegate observation unavailable");
    }
  }

  private static final class Witness {
    final KeycloakSessionFactory factory; final String realm; final long connection;
    final AtomicBoolean blocked = new AtomicBoolean(), sent = new AtomicBoolean(), committed = new AtomicBoolean();
    final AtomicBoolean finished = new AtomicBoolean(), failed = new AtomicBoolean();
    Witness(KeycloakSessionFactory factory, String realm, long connection) {
      this.factory = factory; this.realm = realm; this.connection = connection;
    }
    public String toString() { return "NativeOtpWriterProof[redacted]"; }
  }

  private static void observe(Witness witness) {
    try (var session = witness.factory.create()) {
      var tx = session.getTransactionManager(); tx.begin();
      try {
        var em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
        long deadline = System.nanoTime() + 3_500_000_000L;
        while (!witness.finished.get() && System.nanoTime() < deadline) {
          var rows = em.createNativeQuery("select SESSION_ID, SESSION_STATE, BLOCKER_ID, EXECUTING_STATEMENT from INFORMATION_SCHEMA.SESSIONS where BLOCKER_ID=:writer")
              .setParameter("writer", witness.connection).getResultList();
          for (Object raw : rows) {
            var row = (Object[]) raw;
            String sql = row[3] == null ? "" : row[3].toString().toLowerCase(java.util.Locale.ROOT)
                .replace('"', ' ').replaceAll("\\s+", " ").trim();
            boolean exact = sql.matches("select .+ from (public\\.)?realm [a-z0-9_]+ where [a-z0-9_]+\\.id=\\? for update \\{1: '"
                + java.util.regex.Pattern.quote(witness.realm) + "'\\}");
            if (((Number) row[0]).longValue() != witness.connection && "BLOCKED".equals(row[1])
                && row[2] instanceof Number n && n.longValue() == witness.connection && exact) {
              witness.blocked.set(true); emit("BLOCKED", witness); return;
            }
          }
          Thread.sleep(25);
        }
      } finally { if (tx.isActive()) tx.rollback(); }
    } catch (InterruptedException interrupted) {
      Thread.currentThread().interrupt(); witness.failed.set(true); emit("FAILED", witness);
    } catch (RuntimeException failure) { witness.failed.set(true); emit("FAILED", witness); }
  }

  private static void emit(String phase, Witness witness) {
    var value = new TreeMap<String, Object>(); value.put("schema", 1); value.put("phase", phase);
    value.put("actualNativeWriterTransaction", true); value.put("exactPrivateSendingOrigin", true);
    value.put("runtimeH2Pinned", true); value.put("exactNativeDefaultDelegate", true);
    value.put("cancelBlockedByCapturedWriter", witness.blocked.get());
    value.put("defaultSmtpReturned", witness.sent.get()); value.put("writerCommitted", witness.committed.get());
    value.put("observerFailed", witness.failed.get());
    try { System.out.println(PREFIX + new ObjectMapper().writeValueAsString(value)); }
    catch (java.io.IOException failure) { throw new IllegalStateException("Proof observation unavailable"); }
  }
}
