package de.onlineberatung.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.Assume.assumeTrue;

import de.onlineberatung.RealmOtpResourceProviderFactory;
import java.util.Map;
import org.junit.Test;

/**
 * Valid values use app.oriso-test.internal: `.internal` is reserved for private use (ICANN,
 * 2024) and is not one of the documentation placeholders the check rejects.
 */
public class AppBaseUrlTest {

  private static final String VALID = "https://app.oriso-test.internal";

  @Test
  public void acceptsAnAbsoluteHttpsOrigin() {
    assertThat(AppBaseUrl.require(VALID)).isEqualTo(VALID);
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
    assertRejected("app.oriso-test.internal");
    assertRejected("/login");
  }

  @Test
  public void rejectsNonHttpSchemes() {
    assertRejected("ftp://app.oriso-test.internal");
    assertRejected("javascript:alert(1)");
  }

  @Test
  public void rejectsAPathOrTrailingSlash() {
    // The theme appends /datenschutz etc.; a path or slash would double up.
    assertRejected(VALID + "/");
    assertRejected(VALID + "/app");
    assertRejected(VALID + "?x=1");
  }

  @Test
  public void rejectsPortsOutsideTheValidRange() {
    // java.net.URI hands back 65536 or 99999 as a port instead of refusing them.
    assertRejected("https://app.oriso-test.internal:65536");
    assertRejected("https://app.oriso-test.internal:99999");
    assertRejected("https://app.oriso-test.internal:0");
    assertThat(AppBaseUrl.require(VALID + ":65535")).isEqualTo(VALID + ":65535");
  }

  @Test
  public void rejectsAReservedDomainWithATerminalDnsDot() {
    // getHost() keeps the root dot, so "example.com." would otherwise pass.
    assertRejected("https://example.com.");
    assertRejected("https://app.example.com.");
  }

  @Test
  public void rejectsUserInfo() {
    assertRejected("https://user@app.oriso-test.internal");
  }

  @Test
  public void rejectsAFragment() {
    assertRejected(VALID + "#footer");
  }

  @Test
  public void rejectsChartPlaceholders() {
    assertRejected("https://your-domain.example.com");
    assertRejected("https://your-domain.oriso-test.internal");
  }

  @Test
  public void rejectsReservedDocumentationDomainsLikeUserServiceAndHelm() {
    for (String domain : new String[] {"example.com", "example.org", "example.net", "example.test"}) {
      assertRejected("https://" + domain);
      assertRejected("https://app." + domain);
      assertRejected("https://APP." + domain.toUpperCase(java.util.Locale.ROOT) + ":8443");
    }
    assertRejected("https://app.invalid");
    assertRejected("https://invalid");
  }

  @Test
  public void acceptsHostsThatOnlyResembleAReservedDomain() {
    assertThat(AppBaseUrl.require("https://myexample.org")).isEqualTo("https://myexample.org");
    assertThat(AppBaseUrl.require("https://example.org.oriso-test.internal"))
        .isEqualTo("https://example.org.oriso-test.internal");
  }

  @Test
  public void rejectsAnUnresolvedPlaceholder() {
    assertRejected("${env.ORISO_APP_BASE_URL}");
  }

  @Test
  public void readsTheValueFromTheNamedVariable() {
    Map<String, String> env = Map.of("ORISO_APP_BASE_URL", VALID);
    assertThat(AppBaseUrl.requireFromEnvironment(env::get)).isEqualTo(VALID);
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
