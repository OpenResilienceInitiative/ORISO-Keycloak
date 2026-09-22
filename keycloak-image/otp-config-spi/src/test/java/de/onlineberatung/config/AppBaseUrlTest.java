package de.onlineberatung.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.Assume.assumeTrue;

import de.onlineberatung.RealmOtpResourceProviderFactory;
import java.util.Map;
import org.junit.Test;

public class AppBaseUrlTest {

  @Test
  public void acceptsAnAbsoluteHttpsOrigin() {
    assertThat(AppBaseUrl.require("https://app.example.org")).isEqualTo("https://app.example.org");
  }

  @Test
  public void acceptsAnHttpOriginWithPortForLocalSetups() {
    assertThat(AppBaseUrl.require(" http://localhost:9001 ")).isEqualTo("http://localhost:9001");
  }

  @Test
  public void rejectsAMissingValueAndNamesTheVariable() {
    assertRejected(null);
  }

  @Test
  public void rejectsABlankValue() {
    assertRejected("   ");
  }

  @Test
  public void rejectsARelativeValue() {
    assertRejected("app.example.org");
    assertRejected("/login");
  }

  @Test
  public void rejectsNonHttpSchemes() {
    assertRejected("ftp://app.example.org");
    assertRejected("javascript:alert(1)");
  }

  @Test
  public void rejectsAPathOrTrailingSlash() {
    // The theme appends /datenschutz etc.; a path or slash would double up.
    assertRejected("https://app.example.org/");
    assertRejected("https://app.example.org/app");
    assertRejected("https://app.example.org?x=1");
  }

  @Test
  public void rejectsChartPlaceholders() {
    assertRejected("https://your-domain.example.com");
    assertRejected("https://app.example.com");
  }

  @Test
  public void rejectsAnUnresolvedPlaceholder() {
    assertRejected("${env.ORISO_APP_BASE_URL}");
  }

  @Test
  public void readsTheValueFromTheNamedVariable() {
    Map<String, String> env = Map.of("ORISO_APP_BASE_URL", "https://dev.example.org");
    assertThat(AppBaseUrl.requireFromEnvironment(env::get)).isEqualTo("https://dev.example.org");
  }

  @Test
  public void providerFactoryInitStopsKeycloakWithoutTheVariable() {
    // Factory init runs at server start; throwing there keeps Keycloak from starting.
    assumeTrue(System.getenv(AppBaseUrl.ENV_NAME) == null);

    assertThatThrownBy(() -> new RealmOtpResourceProviderFactory().init(null))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("ORISO_APP_BASE_URL");
  }

  private static void assertRejected(String value) {
    assertThatThrownBy(() -> AppBaseUrl.require(value))
        .isInstanceOf(IllegalStateException.class)
        .hasMessageContaining("ORISO_APP_BASE_URL");
  }
}
