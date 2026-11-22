package de.onlineberatung;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Set;
import java.util.TreeSet;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Role sets of the service identities seeded by realm.json (ORISO-Helm#367). The Helm chart
 * carries a copy of this file; its tests assert the same sets.
 */
public class RealmServiceIdentitiesTest {

  static final String SERVICE_ADMIN = "svc-keycloak-admin";

  private static JsonNode realm;

  @BeforeClass
  public static void loadRealm() throws IOException {
    Path realmJson = Path.of(System.getProperty("basedir")).resolve("../../realm.json");
    realm = new ObjectMapper().readTree(realmJson.toFile());
  }

  @Test
  public void the_realm_defines_the_dedicated_otp_config_admin_role() {
    assertThat(realmRoleNames()).contains("otp-config-admin");
  }

  @Test
  public void the_service_admin_holds_exactly_the_user_management_roles() {
    var user = user(SERVICE_ADMIN);

    assertThat(names(user.path("realmRoles")))
        .containsExactlyInAnyOrder("default-roles-online-beratung", "otp-config-admin");
    assertThat(fieldNames(user.path("clientRoles"))).containsExactly("realm-management");
    assertThat(names(user.path("clientRoles").path("realm-management")))
        .containsExactlyInAnyOrder("manage-users", "view-users", "query-users", "view-realm");
  }

  @Test
  public void the_service_admin_ships_without_a_password() {
    // The password comes from the deployment's secret values, never from the public realm file.
    assertThat(user(SERVICE_ADMIN).path("credentials")).isEmpty();
  }

  @Test
  public void technical_is_a_pure_service_identity() {
    var user = user("technical");

    assertThat(names(user.path("realmRoles")))
        .containsExactlyInAnyOrder("default-roles-online-beratung", "technical");
    assertThat(user.path("clientRoles").size()).isZero();
  }

  @Test
  public void the_unused_technical_default_role_is_gone() {
    assertThat(realmRoleNames()).doesNotContain("TECHNICAL_DEFAULT");
  }

  @Test
  public void no_service_identity_holds_an_admin_role() {
    for (String username : new String[] {"technical", SERVICE_ADMIN}) {
      var user = user(username);
      assertThat(names(user.path("realmRoles")))
          .as(username)
          .doesNotContain("tenant-admin", "single-tenant-admin", "user-admin", "agency-admin");
      assertThat(names(user.path("clientRoles").path("realm-management")))
          .as(username)
          .doesNotContain("realm-admin", "manage-realm", "manage-clients", "impersonation");
    }
  }

  static JsonNode user(String username) {
    for (JsonNode user : realm.path("users")) {
      if (username.equals(user.path("username").asText())) {
        return user;
      }
    }
    throw new AssertionError("realm.json has no user " + username);
  }

  static Set<String> realmRoleNames() {
    Set<String> names = new TreeSet<>();
    realm.path("roles").path("realm").forEach(role -> names.add(role.path("name").asText()));
    return names;
  }

  static Set<String> names(JsonNode array) {
    Set<String> names = new TreeSet<>();
    array.forEach(name -> names.add(name.asText()));
    return names;
  }

  static Set<String> fieldNames(JsonNode object) {
    Set<String> names = new TreeSet<>();
    object.fieldNames().forEachRemaining(names::add);
    return names;
  }

  static JsonNode realm() {
    return realm;
  }
}
