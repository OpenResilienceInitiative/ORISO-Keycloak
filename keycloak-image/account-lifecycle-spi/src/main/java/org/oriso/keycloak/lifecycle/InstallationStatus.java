package org.oriso.keycloak.lifecycle;

import static org.oriso.keycloak.lifecycle.LifecycleJson.*;
import com.fasterxml.jackson.databind.JsonNode;
import jakarta.ws.rs.ServiceUnavailableException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.*;
import java.util.function.Function;
import org.keycloak.models.KeycloakSession;
import org.keycloak.services.resource.RealmResourceProvider;

/** Fixed non-secret readback of loaded provider configuration; it grants no account authority. */
final class InstallationStatus {
  static final String VERSION = "scenario-c-installation-v1";
  private final JsonNode groups;
  private final JsonNode bindings;
  private final String realmId;
  private final String keyVersion;

  InstallationStatus(Function<String, String> environment, JsonNode groups) {
    this.groups = groups.deepCopy();
    realmId = environment.apply("KEYCLOAK_REALM_INTERNAL_ID");
    keyVersion = environment.apply("ORISO_TASK_CONTEXT_KEY_VERSION");
    var loaded = JSON.createObjectNode();
    for (String actor : new TreeSet<>(ProtectedInvitationConfiguration.ACTORS)) {
      var binding = loaded.putObject(actor);
      binding.put("clientId", environment.apply("IDENTITY_" + actor + "_CLIENT_ID"));
      binding.put("serviceSubject", environment.apply("IDENTITY_" + actor + "_SERVICE_SUBJECT"));
    }
    bindings = loaded;
  }

  JsonNode read(KeycloakSession session, LifecycleAuthorization authorization, GeneralPolicy ordinary) {
    var realm = session.getContext().getRealm();
    if (realmId == null || !realmId.equals(realm.getId()) || keyVersion == null
        || !keyVersion.matches("[1-9][0-9]{0,8}")) unavailable();
    var protectedPolicy = ProtectedInvitationFactory.checkedBootstrapConfiguration(session);
    if (!realmId.equals(protectedPolicy.realmId) || !authorization.realmName.equals(protectedPolicy.realmName)) unavailable();
    for (String actor : ProtectedInvitationConfiguration.ACTORS) {
      var binding = bindings.path(actor);
      if (!("backend-" + actor.toLowerCase(Locale.ROOT).replace('_', '-')).equals(binding.path("clientId").asText())
          || !protectedPolicy.actors.get(actor).equals(binding.path("serviceSubject").asText())) unavailable();
    }
    if (!authorization.creatorSubject.equals(protectedPolicy.actors.get("ACCOUNT_CREATE"))
        || !authorization.adminSubject.equals(protectedPolicy.actors.get("ACCOUNT_ADMIN"))) unavailable();
    // These are current native checks, not just startup-ready flags or supplied manifest hashes.
    ordinary.validateInstallation(session);
    protectedPolicy.validateInstallation(session);
    var result = JSON.createObjectNode();
    result.put("version", 1);
    result.put("providerVersion", VERSION);
    result.put("realmId", realmId);
    result.put("realmName", realm.getName());
    result.put("contextKeyVersion", keyVersion);
    result.put("bindingsSha256", fingerprint(bindings));
    result.put("ordinaryGroupsSha256", fingerprint(groups));
    result.put("ordinaryPolicySha256", fingerprint(ordinary.installation));
    result.put("protectedPolicySha256", fingerprint(protectedPolicy.installation));
    var providers = result.putObject("providerJarSha256");
    for (String id : List.of("oriso-account-lifecycle", "otp-config", "oriso-smtp-control")) {
      var factory = session.getKeycloakSessionFactory().getProviderFactory(RealmResourceProvider.class, id);
      if (factory == null) unavailable();
      providers.put(id, jarFingerprint(factory.getClass()));
    }
    return result;
  }

  static String fingerprint(JsonNode value) {
    try {
      return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
          .digest(canonical(value).getBytes(StandardCharsets.UTF_8)));
    } catch (java.security.NoSuchAlgorithmException failure) { throw new IllegalStateException(failure); }
  }

  static String jarFingerprint(Class<?> provider) {
    try {
      var source = provider.getProtectionDomain().getCodeSource();
      if (source == null || !"file".equals(source.getLocation().getProtocol())) unavailable();
      Path path = Path.of(source.getLocation().toURI());
      if (!Files.isRegularFile(path) || !path.getFileName().toString().endsWith(".jar")
          || Files.size(path) > 32 * 1024 * 1024) unavailable();
      try (var input = Files.newInputStream(path)) {
        var digest = MessageDigest.getInstance("SHA-256");
        byte[] buffer = new byte[8192];
        for (int count; (count = input.read(buffer)) >= 0;) digest.update(buffer, 0, count);
        return HexFormat.of().formatHex(digest.digest());
      }
    } catch (Exception failure) { throw new ServiceUnavailableException(); }
  }

  private static void unavailable() { throw new ServiceUnavailableException(); }
}
