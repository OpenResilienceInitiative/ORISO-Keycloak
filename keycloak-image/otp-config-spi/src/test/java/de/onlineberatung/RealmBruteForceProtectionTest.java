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
 * <p>Keycloak counts every failed step of the direct grant, including the 400 "Missing totp"
 * challenge that asks for the e-mail code. A legitimate e-mail sign-in can therefore collect
 * 1 challenge + 5 resends + 3 wrong codes = 9 failures before the success clears them; the factor
 * must stay well above that.
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
    assertThat(realm.path("bruteForceStrategy").asText()).isEqualTo("MULTIPLE");
    assertThat(realm.path("maxFailureWaitSeconds").asInt()).isEqualTo(900);
  }

  @Test
  public void a_legitimate_email_sign_in_cannot_reach_the_failure_factor() {
    int challenge = 1;
    int resends = 5;
    int wrongCodes = 3;
    assertThat(realm.path("failureFactor").asInt()).isEqualTo(15)
        .isGreaterThan(challenge + resends + wrongCodes);
    assertThat(realm.path("waitIncrementSeconds").asInt()).isEqualTo(60);
    assertThat(realm.path("maxDeltaTimeSeconds").asInt()).isEqualTo(43200);
  }

  @Test
  public void two_quick_failures_cost_seconds_not_a_minute() {
    // A double-clicked resend produces two failures within a second; with Keycloak's
    // default of 60 s the user would be locked out with the right code in hand.
    assertThat(realm.path("quickLoginCheckMilliSeconds").asInt()).isEqualTo(1000);
    assertThat(realm.path("minimumQuickLoginWaitSeconds").asInt()).isEqualTo(5);
  }
}
