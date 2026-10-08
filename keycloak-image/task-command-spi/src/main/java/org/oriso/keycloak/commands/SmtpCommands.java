package org.oriso.keycloak.commands;

import static org.oriso.keycloak.commands.CommandValidation.*;

import com.fasterxml.jackson.databind.JsonNode;
import jakarta.mail.internet.AddressException;
import jakarta.mail.internet.InternetAddress;
import jakarta.persistence.EntityManager;
import jakarta.persistence.LockModeType;
import jakarta.ws.rs.ClientErrorException;
import jakarta.ws.rs.core.Response;
import java.util.*;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailSenderProvider;
import org.keycloak.models.*;
import org.oriso.keycloak.auth.*;

/** Only SMTP configuration crosses this boundary; no RealmRepresentation is accepted. */
final class SmtpCommands {
  private final KeycloakSession session;
  private final OriginAuthorization origins;

  SmtpCommands(KeycloakSession session, OriginAuthorization origins) {
    this.session = session;
    this.origins = origins;
  }

  Response apply(JsonNode body) {
    var caller = TaskIdentity.require(session, "smtp-sync", "smtp-sync");
    fields(
        body,
        "revision",
        "globalSmtpEnabled",
        "globalFeatureSystemNotificationEmailsEnabled",
        "globalSmtpHost",
        "globalSmtpPort",
        "globalSmtpFrom",
        "globalSmtpUsername",
        "globalSmtpPassword",
        "globalSmtpSecure");
    JsonNode revisionNode = body.get("revision");
    if (revisionNode == null
        || !revisionNode.isIntegralNumber()
        || !revisionNode.canConvertToLong()
        || revisionNode.asLong() < 0) bad();
    long revision = revisionNode.asLong();
    RealmModel realm = session.getContext().getRealm();
    EntityManager em = session.getProvider(JpaConnectionProvider.class).getEntityManager();
    SmtpRevision saved = em.find(SmtpRevision.class, realm.getId(), LockModeType.PESSIMISTIC_WRITE);
    String fingerprint = origins.fingerprint(body);
    if (saved != null
        && (revision < saved.revision
            || (revision == saved.revision && !fingerprint.equals(saved.fingerprint))))
      throw new ClientErrorException("SMTP revision is stale or conflicting", 409);
    Map<String, String> config = snapshot(body);
    if (saved == null) {
      saved = new SmtpRevision();
      saved.realmId = realm.getId();
      saved.revision = revision;
      saved.fingerprint = fingerprint;
      em.persist(saved);
    } else {
      saved.revision = revision;
      saved.fingerprint = fingerprint;
    }
    realm.setSmtpConfig(config);
    String status = config.isEmpty() ? "DISABLED_OR_INCOMPLETE" : "APPLIED";
    CommandAudit.record(
        session,
        caller,
        org.keycloak.events.admin.OperationType.UPDATE,
        "ORISO_SMTP_COMMAND",
        "smtp",
        Map.of("revision", revision, "status", status));
    return Response.ok(Map.of("revision", revision, "status", status))
        .header("Cache-Control", "no-store")
        .build();
  }

  private Map<String, String> snapshot(JsonNode body) {
    for (String field :
        List.of(
            "globalSmtpEnabled",
            "globalFeatureSystemNotificationEmailsEnabled",
            "globalSmtpSecure")) {
      JsonNode value = body.get(field);
      if (value != null && !value.isNull() && !value.isBoolean()) bad();
    }
    String host = text(body, "globalSmtpHost", false, 255),
        from = text(body, "globalSmtpFrom", false, 255),
        username = opaque(body, "globalSmtpUsername"),
        password = opaque(body, "globalSmtpPassword");
    String port = null;
    JsonNode value = body.get("globalSmtpPort");
    if (value != null && !value.isNull()) {
      if (value.isIntegralNumber() && value.canConvertToInt()) port = value.asText();
      else if (value.isTextual() && value.asText().matches("[0-9]{1,5}")) port = value.asText();
      else bad();
      try {
        int number = Integer.parseInt(port);
        if (number < 1 || number > 65535) bad();
      } catch (NumberFormatException e) {
        bad();
      }
    }
    if (!body.path("globalSmtpEnabled").asBoolean()
        || !body.path("globalFeatureSystemNotificationEmailsEnabled").asBoolean()
        || host == null
        || host.isBlank()
        || from == null
        || from.isBlank()
        || port == null
        || username == null
        || username.isEmpty()
        || password == null
        || password.isEmpty()
        || !body.path("globalSmtpSecure").isBoolean()) return Map.of();
    boolean secure = body.path("globalSmtpSecure").asBoolean();
    Map<String, String> config = new LinkedHashMap<>();
    config.put("host", host.trim());
    config.put("port", port);
    config.put("ssl", Boolean.toString(secure));
    config.put("starttls", Boolean.toString(!secure));
    config.put("auth", "true");
    try {
      InternetAddress[] senders = InternetAddress.parse(from.trim(), true);
      if (senders.length != 1 || senders[0].isGroup()) bad();
      var sender = senders[0];
      sender.validate();
      String mailbox = sender.getAddress();
      if (mailbox == null || mailbox.chars().filter(c -> c == '@').count() != 1) bad();
      config.put("from", mailbox);
      String personal = sender.getPersonal();
      config.put(
          "fromDisplayName",
          personal == null || personal.isBlank()
              ? System.getenv().getOrDefault("EMAIL_BRANDING_NAME", "ORISO")
              : personal);
    } catch (AddressException failure) {
      bad();
    }
    config.put("user", username);
    config.put("password", password);
    try {
      session.getProvider(EmailSenderProvider.class).validate(config);
    } catch (EmailException failure) {
      bad();
    }
    return config;
  }

  private String opaque(JsonNode body, String field) {
    JsonNode value = body.get(field);
    if (value == null || value.isNull()) return null;
    if (!value.isTextual() || value.asText().length() > 4096) bad();
    return value.asText();
  }
}
