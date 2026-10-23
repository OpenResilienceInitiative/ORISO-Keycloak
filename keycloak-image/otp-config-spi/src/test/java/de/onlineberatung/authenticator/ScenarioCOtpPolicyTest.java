package de.onlineberatung.authenticator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.HashMap;
import java.util.Map;
import org.junit.Test;

public class ScenarioCOtpPolicyTest {
  @Test
  public void absentModelKeepsLegacyWithoutNewConfiguration() {
    assertThat(ScenarioCOtpPolicy.fromEnvironment(key -> null)).isNull();
  }

  @Test
  public void onlyExplicitFiveActorsEnablesTheReceiver() {
    assertThatThrownBy(() -> ScenarioCOtpPolicy.fromEnvironment(key -> "LEGACY"))
        .isInstanceOf(IllegalStateException.class);
    assertThat(ScenarioCOtpPolicy.fromEnvironment(configuration()::get)).isNotNull();
  }

  @Test
  public void optedInReceiverRequiresCanonicalClientAndExplicitSubject() {
    var config = configuration();
    config.remove("IDENTITY_ACCOUNT_ADMIN_SERVICE_SUBJECT");
    assertThatThrownBy(() -> ScenarioCOtpPolicy.fromEnvironment(config::get))
        .isInstanceOf(IllegalStateException.class);
    var wrongClient = configuration();
    wrongClient.put("IDENTITY_ACCOUNT_ADMIN_CLIENT_ID", "backend-admin");
    assertThatThrownBy(() -> ScenarioCOtpPolicy.fromEnvironment(wrongClient::get))
        .isInstanceOf(IllegalStateException.class);
  }

  @Test
  public void invalidOrNonCanonicalSubjectCannotActivate() {
    for (String subject : new String[] {"not-a-subject", "3BA0A596-5D19-4D9C-AE86-78649A30B543"}) {
      var config = configuration();
      config.put("IDENTITY_ACCOUNT_ADMIN_SERVICE_SUBJECT", subject);
      assertThatThrownBy(() -> ScenarioCOtpPolicy.fromEnvironment(config::get))
          .isInstanceOf(IllegalStateException.class);
    }
  }

  private static Map<String, String> configuration() {
    var config = new HashMap<String, String>();
    config.put("TASK_IDENTITY_MODEL", "FIVE_ACTORS");
    config.put("IDENTITY_ACCOUNT_ADMIN_CLIENT_ID", "backend-account-admin");
    config.put("IDENTITY_ACCOUNT_ADMIN_SERVICE_SUBJECT", "3ba0a596-5d19-4d9c-ae86-78649a30b543");
    return config;
  }
}
