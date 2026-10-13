package de.onlineberatung;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.nio.file.Path;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Brute-force protection seeded by realm.json (ORISO-UserService#1338, slice 5). The Helm chart
 * carries a copy of this file; its tests assert the same values.
 *
 * <p>OTP prompts are pending authentication steps, not rejected credentials. Only genuine
 * credential failures consume the account's failure budget. The runtime integration test
 * checks that distinction on the actual image; these tests pin the realm configuration.
 */
public class RealmBruteForceProtectionTest {

  private static JsonNode realm;

  @BeforeClass
  public static void loadRealm() throws IOException {
    Path realmJson = Path.of(System.getProperty("basedir")).resolve("../../realm.json");
    realm = new ObjectMapper().readTree(realmJson.toFile());
  }

  @Test
  public void brute_force_protection_is_on() {
    assertThat(realm.path("bruteForceProtected").asBoolean()).isTrue();
  }

  @Test
  public void lockout_is_only_ever_temporary() {
    assertThat(realm.path("permanentLockout").asBoolean()).isFalse();
    assertThat(realm.path("maxTemporaryLockouts").asInt()).isZero();
    assertThat(realm.has("maxSecondaryAuthFailures")).isTrue();
    assertThat(realm.path("maxSecondaryAuthFailures").asInt()).isZero();
    assertThat(realm.path("bruteForceStrategy").asText()).isEqualTo("MULTIPLE");
    assertThat(realm.path("maxFailureWaitSeconds").asInt()).isEqualTo(900);
  }

  @Test
  public void real_credential_failures_keep_the_agreed_threshold_and_idle_window() {
    assertThat(realm.path("failureFactor").asInt()).isEqualTo(15);
    assertThat(realm.path("waitIncrementSeconds").asInt()).isEqualTo(60);
    assertThat(realm.path("maxDeltaTimeSeconds").asInt()).isEqualTo(43200);
  }

  @Test
  public void two_quick_failures_cost_seconds_not_a_minute() {
    // Pending OTP prompts do not count; two actual quick credential failures use this wait.
    assertThat(realm.path("quickLoginCheckMilliSeconds").asInt()).isEqualTo(1000);
    assertThat(realm.path("minimumQuickLoginWaitSeconds").asInt()).isEqualTo(5);
  }
}
