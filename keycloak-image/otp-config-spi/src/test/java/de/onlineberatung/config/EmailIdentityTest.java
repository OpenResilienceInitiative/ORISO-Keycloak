package de.onlineberatung.config;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Map;
import org.junit.Test;

public class EmailIdentityTest {

  @Test
  public void requiresBothSeparateInstallationValues() {
    var configured = Map.of(
        EmailIdentity.PRODUCT_ENV, "Care Portal",
        EmailIdentity.LEGAL_ORGANISATION_ENV, "Example Foundation e.V.");
    EmailIdentity.requireFromEnvironment(configured::get);

    for (String omitted : configured.keySet()) {
      assertThatThrownBy(() -> EmailIdentity.requireFromEnvironment(name ->
          omitted.equals(name) ? null : configured.get(name)))
          .isInstanceOf(IllegalStateException.class)
          .hasMessageContaining(omitted)
          .hasMessageNotContaining("Example Foundation");
    }
  }

  @Test
  public void rejectsBlankUnresolvedAndHeaderBreakingValuesWithoutLoggingThem() {
    for (String value : new String[] {"  ", "${env.EMAIL_BRANDING_NAME}", "bad\nname"}) {
      assertThatThrownBy(() -> EmailIdentity.require(EmailIdentity.PRODUCT_ENV, value))
          .isInstanceOf(IllegalStateException.class)
          .hasMessageContaining(EmailIdentity.PRODUCT_ENV)
          .hasMessageNotContaining(value);
    }
  }
}
