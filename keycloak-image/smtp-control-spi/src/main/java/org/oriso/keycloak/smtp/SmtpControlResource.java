package org.oriso.keycloak.smtp;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.mail.internet.AddressException;
import jakarta.mail.internet.InternetAddress;
import jakarta.persistence.LockModeType;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.ForbiddenException;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailSenderProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.jpa.entities.RealmEntity;
import org.keycloak.services.resource.RealmResourceProvider;

@jakarta.ws.rs.ext.Provider
@jakarta.enterprise.inject.Vetoed
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
public final class SmtpControlResource implements RealmResourceProvider {
  private static final Set<String> FIELDS = Set.of(
      "revision", "globalSmtpEnabled", "globalFeatureSystemNotificationEmailsEnabled",
      "globalSmtpHost", "globalSmtpPort", "globalSmtpFrom", "globalSmtpUsername",
      "globalSmtpPassword", "globalSmtpSecure");
  private final KeycloakSession session;
  private final SmtpAuthorization authorization;

  SmtpControlResource(KeycloakSession session, SmtpAuthorization authorization) {
    this.session = session;
    this.authorization = authorization;
  }

  @PUT
  @Path("v1/smtp")
  public Response apply(String raw, @HeaderParam("X-ORISO-Task-Context") String proof) {
    enabled();
    JsonNode body;
    try {
      if (raw == null || raw.length() > 16384) bad();
      body = SmtpAuthorization.JSON.readTree(raw);
      if (body == null || !body.isObject()) bad();
    } catch (BadRequestException failure) {
      throw failure;
    } catch (Exception failure) {
      throw new BadRequestException("Invalid SMTP snapshot");
    }
    String fingerprint = authorization.require(session, proof, "SMTP_APPLY", "PUT", body);
    body.fieldNames().forEachRemaining(field -> { if (!FIELDS.contains(field)) bad(); });
    JsonNode revisionNode = body.path("revision");
    if (!revisionNode.isIntegralNumber() || !revisionNode.canConvertToLong() || revisionNode.asLong() < 0) bad();
    long revision = revisionNode.asLong();
    Map<String, String> config = snapshot(body);
    var realm = session.getContext().getRealm();
    var em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
    // A stable existing row serializes even the first command. Both writes use
    // Keycloak's request transaction, so failures never consume a revision.
    var lockedRealm = em.find(RealmEntity.class, realm.getId(), LockModeType.PESSIMISTIC_WRITE);
    em.refresh(lockedRealm);
    var saved = em.find(SmtpRevision.class, realm.getId(), LockModeType.PESSIMISTIC_WRITE);
    boolean created = saved == null;
    if (saved != null) {
      if (revision < saved.revision || (revision == saved.revision && !fingerprint.equals(saved.fingerprint)))
        throw new ClientErrorException("SMTP revision is stale or conflicting", 409);
      if (revision == saved.revision) return result(saved.revision, saved.status);
    } else {
      saved = new SmtpRevision();
      saved.realmId = realm.getId();
    }
    saved.revision = revision;
    saved.fingerprint = fingerprint;
    saved.status = config.isEmpty() ? "DISABLED_OR_INCOMPLETE" : "APPLIED";
    if (created) em.persist(saved);
    realm.setSmtpConfig(config);
    return result(saved.revision, saved.status);
  }

  @GET
  @Path("v1/smtp")
  public Response status(@HeaderParam("X-ORISO-Task-Context") String proof) {
    enabled();
    authorization.require(session, proof, "SMTP_STATUS", "GET", SmtpAuthorization.JSON.createObjectNode());
    var em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
    var saved = em.find(SmtpRevision.class, session.getContext().getRealm().getId());
    return saved == null ? result(-1, "NOT_APPLIED") : result(saved.revision, saved.status);
  }

  private Map<String, String> snapshot(JsonNode body) {
    for (String field : Set.of("globalSmtpEnabled", "globalFeatureSystemNotificationEmailsEnabled", "globalSmtpSecure")) {
      JsonNode value = body.get(field);
      if (value != null && !value.isNull() && !value.isBoolean()) bad();
    }
    String host = text(body, "globalSmtpHost", 255), from = text(body, "globalSmtpFrom", 255),
        username = text(body, "globalSmtpUsername", 4096), password = text(body, "globalSmtpPassword", 4096);
    String port = null;
    JsonNode value = body.get("globalSmtpPort");
    if (value != null && !value.isNull()) {
      if (value.isIntegralNumber() && value.canConvertToInt()) port = value.asText();
      else if (value.isTextual() && value.asText().matches("[0-9]{1,5}")) port = value.asText();
      else bad();
      try {
        int number = Integer.parseInt(port);
        if (number < 1 || number > 65535) bad();
      } catch (NumberFormatException failure) { bad(); }
    }
    Map<String, String> config = new LinkedHashMap<>();
    if (from != null && !from.isBlank()) try {
      InternetAddress[] senders = InternetAddress.parse(from.trim(), true);
      if (senders.length != 1 || senders[0].isGroup()) bad();
      senders[0].validate();
      String mailbox = senders[0].getAddress();
      if (mailbox == null || mailbox.chars().filter(character -> character == '@').count() != 1) bad();
      config.put("from", mailbox);
      String personal = senders[0].getPersonal();
      config.put("fromDisplayName", personal == null || personal.isBlank()
          ? System.getenv().getOrDefault("EMAIL_BRANDING_NAME", "ORISO") : personal);
    } catch (AddressException failure) { bad(); }
    if (!body.path("globalSmtpEnabled").asBoolean() || !body.path("globalFeatureSystemNotificationEmailsEnabled").asBoolean()
        || host == null || host.isBlank() || from == null || from.isBlank() || port == null
        || username == null || username.isEmpty() || password == null || password.isEmpty()
        || !body.path("globalSmtpSecure").isBoolean()) return Map.of();
    config.put("host", host.trim());
    config.put("port", port);
    config.put("ssl", Boolean.toString(body.path("globalSmtpSecure").asBoolean()));
    config.put("starttls", Boolean.toString(!body.path("globalSmtpSecure").asBoolean()));
    config.put("auth", "true");
    config.put("user", username);
    config.put("password", password);
    try {
      session.getProvider(EmailSenderProvider.class).validate(config);
    } catch (EmailException failure) { bad(); }
    return config;
  }

  private static String text(JsonNode body, String field, int limit) {
    JsonNode value = body.get(field);
    if (value == null || value.isNull()) return null;
    if (!value.isTextual() || value.asText().length() > limit
        || value.asText().chars().anyMatch(character -> character < 32 || character == 127)) bad();
    return value.asText();
  }

  private void enabled() { if (authorization == null) throw new ForbiddenException("SMTP control is disabled"); }
  private static void bad() { throw new BadRequestException("Invalid SMTP snapshot"); }
  private static Response result(long revision, String status) {
    return Response.ok(Map.of("revision", revision, "status", status)).header("Cache-Control", "no-store").build();
  }
  public Object getResource() { return this; }
  public void close() {}
}
