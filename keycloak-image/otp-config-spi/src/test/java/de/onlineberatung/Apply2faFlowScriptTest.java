package de.onlineberatung;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.Test;

/** The operator script must grant the SPI access role to the admin identity, not to technical. */
public class Apply2faFlowScriptTest {

  private static String script() throws IOException {
    return Files.readString(
        Path.of(System.getProperty("basedir")).resolve("../../scripts/keycloak-apply-2fa-flow.sh"));
  }

  @Test
  public void the_script_no_longer_grants_technical_for_the_spi() throws IOException {
    assertThat(script()).doesNotContain("--uusername technical");
  }

  @Test
  public void the_script_grants_otp_config_admin_to_the_backend_admin_identity() throws IOException {
    var script = script();
    assertThat(script).contains("--rolename otp-config-admin");
    assertThat(script).contains("svc-keycloak-admin");
  }
}
