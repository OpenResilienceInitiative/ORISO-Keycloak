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
import org.keycloak.email.DefaultEmailSenderProviderFactory;
import org.keycloak.models.AbstractKeycloakTransaction;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.UserModel;

/** Disposable native SMTP observer. Always delegates the actual pinned default provider. */
public final class OtpWriterFixtureFactory implements EmailSenderProviderFactory {
  private static final Path CONTROL = Path.of("/opt/keycloak/proof-otp-writer/control.json");
  private static final String PREFIX = "ORISO_PROOF_OTP_WRITER_V1 ";
  private final DefaultEmailSenderProviderFactory nativeFactory = new DefaultEmailSenderProviderFactory();
  public EmailSenderProvider create(KeycloakSession session) {
    delegateObservation("CONSTRUCTION_ENTERED", false, false);
    return new Sender(session, nativeFactory.create(session));
  }
  public void init(Config.Scope scope) { checkSelectorGrammar(); nativeFactory.init(scope); }
  public void postInit(KeycloakSessionFactory factory) { nativeFactory.postInit(factory); }
  public String getId() { return "oriso-proof-otp-writer"; }
  public void close() { nativeFactory.close(); }

  private static final class Sender implements EmailSenderProvider {
    private final KeycloakSession session;
    private final EmailSenderProvider delegate;
    Sender(KeycloakSession session, EmailSenderProvider nativeDelegate) {
      this.session = session;
      delegate = nativeDelegate;
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
      if (Files.isRegularFile(CONTROL)) delegateObservation("SEND_ADDRESS_ENTERED", true, true);
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
      delegateObservation("CAPTURE_ENTERED", true, true);
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
        delegateObservation("CAPTURE_TRANSACTION_VERIFIED", true, true);
        var rows = em.createNativeQuery("select STATE from ORISO_OTP_EMAIL_DELIVERY where ID=:id and REALM_ID=:realm and ACCOUNT_ID=:account")
            .setParameter("id", realm + ":" + control.path("operationId").textValue())
            .setParameter("realm", realm).setParameter("account", account).getResultList();
        if (rows.size() != 1 || !"SENDING".equals(rows.get(0))) throw new IllegalStateException("Actual SENDING owner required");
        delegateObservation("CAPTURE_SENDING_VERIFIED", true, true);
        var bootstrap = em.createNativeQuery("select APPROVAL_ID, ATTEMPT_ID, EXECUTION_ID, STATE from ORISO_PROTECTED_OTP_BOOTSTRAP where REALM_ID=:realm and ACCOUNT_ID=:account")
            .setParameter("realm", realm).setParameter("account", account).getResultList();
        if (bootstrap.size() != 1) throw new IllegalStateException("Exact bootstrap owner required");
        var b = (Object[]) bootstrap.get(0);
        if (!control.path("approvalId").textValue().equals(b[0]) || !control.path("attemptId").textValue().equals(b[1])
            || !control.path("executionId").textValue().equals(b[2]) || !"EMAIL_READY".equals(b[3]))
          throw new IllegalStateException("Original bootstrap incarnation required");
        delegateObservation("CAPTURE_BOOTSTRAP_VERIFIED", true, true);
        var attempts = em.createNativeQuery("select STATE, GENERATION, EXECUTION_ID from ORISO_ACCOUNT_LIFECYCLE_ATTEMPT where REALM_ID=:realm and ACCOUNT_ID=:account and ATTEMPT_ID=:attempt")
            .setParameter("realm", realm).setParameter("account", account)
            .setParameter("attempt", control.path("attemptId").textValue()).getResultList();
        if (attempts.size() != 1) throw new IllegalStateException("Exact pending attempt required");
        var a = (Object[]) attempts.get(0);
        if (!"OPEN".equals(a[0]) || !(a[1] instanceof Number n) || n.longValue() != 0
            || !control.path("executionId").textValue().equals(a[2])) throw new IllegalStateException("Original OPEN generation required");
        delegateObservation("CAPTURE_ATTEMPT_VERIFIED", true, true);
        long connection = ((Number) em.createNativeQuery("select SESSION_ID()").getSingleResult()).longValue();
        if (connection < 1) throw new IllegalStateException("Actual writer session required");
        var witness = new Witness(session.getKeycloakSessionFactory(), realm, connection);
        emit("ENTERED", witness); return witness;
      } catch (java.io.IOException | RuntimeException failure) {
        delegateObservation("CAPTURE_REJECTED", true, true);
        throw new IllegalStateException("Native writer witness unavailable");
      }
    }
    public void close() { delegate.close(); }
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
        boolean sampled = false;
        long deadline = System.nanoTime() + 3_500_000_000L;
        while (!witness.finished.get() && System.nanoTime() < deadline) {
          var rows = em.createNativeQuery("select SESSION_ID, SESSION_STATE, BLOCKER_ID, EXECUTING_STATEMENT from INFORMATION_SCHEMA.SESSIONS where BLOCKER_ID=:writer")
              .setParameter("writer", witness.connection).getResultList();
          for (Object raw : rows) {
            var row = (Object[]) raw;
            String sql = row[3] == null ? "" : row[3].toString().toLowerCase(java.util.Locale.ROOT)
                .replace('"', ' ').replaceAll("\\s+", " ").trim();
            boolean exact = sql.matches("select .+ from (public\\.)?realm [a-z0-9_]+ where [a-z0-9_]+\\s*\\.\\s*id\\s*=\\s*\\? for update \\{1: '"
                + java.util.regex.Pattern.quote(witness.realm) + "'\\}");
            var selector = realmSelector(sql, witness.realm);
            if (!sampled) {
              sqlTemplate(sql);
              waitObservation(rows.size(), "BLOCKED".equals(row[1]),
                  row[2] instanceof Number blocker && blocker.longValue() == witness.connection,
                  ((Number) row[0]).longValue() != witness.connection,
                  sql.matches(".* from (public\\.)?realm [a-z0-9_]+ .*"),
                  sql.contains(" for update"), sql.endsWith("{1: '" + witness.realm + "'}"), exact, selector);
              sampled = true;
            }
            if (((Number) row[0]).longValue() != witness.connection && "BLOCKED".equals(row[1])
                && row[2] instanceof Number n && n.longValue() == witness.connection && selector.values().stream().allMatch(Boolean::booleanValue)) {
              witness.blocked.set(true); emit("BLOCKED", witness); return;
            }
          }
          Thread.sleep(25);
        }
        if (!sampled) waitObservation(0, false, false, false, false, false, false, false, realmSelector("", witness.realm));
      } finally { if (tx.isActive()) tx.rollback(); }
    } catch (InterruptedException interrupted) {
      Thread.currentThread().interrupt(); witness.failed.set(true); emit("FAILED", witness);
    } catch (RuntimeException failure) { witness.failed.set(true); emit("FAILED", witness); }
  }

  private static Map<String, Boolean> realmSelector(String sql, String realm) {
    int from = sql.indexOf(" from "), where = sql.lastIndexOf(" where ");
    int update = sql.lastIndexOf(" for update ");
    boolean ordered = from >= 0 && where > from && update > where;
    String table = ordered ? sql.substring(from + 6, where).trim().replaceAll("\\s*\\.\\s*", ".") : "";
    String predicate = ordered ? sql.substring(where + 7, update).trim().replaceAll("\\s*\\.\\s*", ".") : "";
    String tail = ordered ? sql.substring(update + 12).trim() : "";
    return Map.of("selectStatement", sql.startsWith("select "),
        "onlyRealmTable", table.matches("(public\\.)?realm(?: [a-z0-9_]+)?"),
        "singlePrimaryKeyPredicate", predicate.matches("(?:[a-z0-9_]+\\.)?id(?:\\s*=\\s*\\?|\\s+in\\s*\\(\\s*\\?\\s*\\))"),
        "onlyForUpdateAndExactRealmBind", tail.equals("{1: '" + realm + "'}"));
  }

  private static void checkSelectorGrammar() {
    String before = "select tbl.id from realm tbl where ", after = " for update {1: 'synthetic'}";
    for (String predicate : new String[] {"tbl.id=?", "tbl.id in (?)"})
      if (!realmSelector(before + predicate + after, "synthetic").values().stream().allMatch(Boolean::booleanValue))
        throw new IllegalStateException("Single native realm selector required");
    for (String sql : new String[] {before + "tbl.id in (?,?)" + after, before + "tbl.idin (?)" + after,
        before + "tbl.id in (?) and tbl.enabled=?" + after,
        before + "tbl.id in (?) or tbl.id=?" + after,
        "select tbl.id from realm tbl join realm other on tbl.id=other.id where tbl.id in (?)" + after,
        "select tbl.id from user_entity tbl where tbl.id in (?)" + after,
        before + "tbl.id in (?) for update {1: 'different'}"})
      if (realmSelector(sql, "synthetic").values().stream().allMatch(Boolean::booleanValue))
        throw new IllegalStateException("Expanded native selector refused");
  }

  private static void sqlTemplate(String sql) {
    // One fixture-only template, never the bound realm or any quoted/numeric literal.
    String sanitized = sql.replaceAll("'(?:''|[^'])*'", "'<BOUND_REALM>'")
        .replaceAll("(?<![a-z0-9_])[0-9]+(?![a-z0-9_])", "<BOUND_REALM>");
    if (sanitized.length() > 16384 || !sanitized.startsWith("select ")
        || !sanitized.contains(" from realm ") || sanitized.contains(";")
        || sanitized.contains("--") || sanitized.contains("/*"))
      throw new IllegalStateException("Sanitized SQL template unavailable");
    try { System.out.println("ORISO_PROOF_OTP_SQL_TEMPLATE_V1 " + new ObjectMapper()
        .writeValueAsString(Map.of("schema", 1, "template", sanitized))); }
    catch (java.io.IOException failure) { throw new IllegalStateException("Sanitized SQL template unavailable"); }
  }

  private static void waitObservation(int count, boolean blocked, boolean blocker, boolean other,
      boolean realm, boolean update, boolean parameter, boolean exact, Map<String, Boolean> selector) {
    var values = new TreeMap<String, Object>();
    values.put("schema", 1); values.put("rowCount", count);
    values.put("nativeBlockedState", blocked); values.put("capturedBlockerMatches", blocker);
    values.put("otherSession", other); values.put("realmTable", realm); values.put("forUpdate", update);
    values.put("realmParameterSuffix", parameter); values.put("exactOriginalGrammar", exact);
    values.putAll(selector);
    try { System.out.println("ORISO_PROOF_OTP_WAIT_V1 " + new ObjectMapper().writeValueAsString(values)); }
    catch (java.io.IOException failure) { throw new IllegalStateException("Proof wait observation unavailable"); }
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
