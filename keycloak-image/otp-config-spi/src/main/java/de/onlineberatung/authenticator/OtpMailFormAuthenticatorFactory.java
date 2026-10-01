package de.onlineberatung.authenticator;

import static java.util.Arrays.asList;

import de.onlineberatung.credential.MailOtpCredentialProviderFactory;
import de.onlineberatung.credential.MailOtpCredentialService;
import de.onlineberatung.mail.DefaultMailSender;
import de.onlineberatung.otp.MemoryOtpService;
import de.onlineberatung.otp.RandomDigitsCodeGenerator;
import java.time.Clock;
import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel.Requirement;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * Registers the browser-flow e-mail OTP authenticator.
 *
 * <p>It deliberately reads the same {@code email-otp-config} alias as {@link
 * OtpMailAuthenticatorFactory}: code length, time-to-live, sender and simulation mode are
 * properties of the realm's e-mail OTP, not of the login surface asking for it. Two configs would
 * let a code that is valid in the app be expired in the browser.
 */
public class OtpMailFormAuthenticatorFactory implements AuthenticatorFactory {

  @Override
  public String getId() {
    return OtpMailFormAuthenticator.AUTHENTICATOR_ID;
  }

  @Override
  public String getDisplayType() {
    return "Email Authentication (browser form)";
  }

  @Override
  public String getHelpText() {
    return "Mails an OTP and asks for it on a form. The browser-flow counterpart to "
        + "\"Email Authentication\", which only works for the direct grant.";
  }

  @Override
  public String getReferenceCategory() {
    return "otp";
  }

  @Override
  public boolean isConfigurable() {
    return true;
  }

  @Override
  public boolean isUserSetupAllowed() {
    return false;
  }

  @Override
  public Requirement[] getRequirementChoices() {
    return new Requirement[]{Requirement.REQUIRED, Requirement.ALTERNATIVE, Requirement.CONDITIONAL,
        Requirement.DISABLED,};
  }

  @Override
  public List<ProviderConfigProperty> getConfigProperties() {
    return asList(
        new ProviderConfigProperty("length", "Code length",
            "The number of digits of the generated code.", ProviderConfigProperty.STRING_TYPE, 6),
        new ProviderConfigProperty("ttl", "Time-to-live",
            "The time to live in seconds for the code to be valid.",
            ProviderConfigProperty.STRING_TYPE, "300"),
        new ProviderConfigProperty("senderId", "SenderId",
            "The sender ID is displayed as the message sender on the receiving device.",
            ProviderConfigProperty.STRING_TYPE, "Keycloak"),
        new ProviderConfigProperty("simulation", "Simulation mode",
            "In simulation mode, the EMAIL won't be sent, but printed to the server logs",
            ProviderConfigProperty.BOOLEAN_TYPE, true)
    );
  }

  @Override
  public Authenticator create(KeycloakSession session) {
    var authConfig = session.getContext().getRealm()
        .getAuthenticatorConfigByAlias(OtpMailAuthenticatorFactory.OTP_CONFIG_ALIAS);
    var generator = new RandomDigitsCodeGenerator();
    var systemClock = Clock.systemDefaultZone();
    var mailOtpCredentialProvider = new MailOtpCredentialProviderFactory().create(session);
    var credentialService = new MailOtpCredentialService(mailOtpCredentialProvider, systemClock);
    var otpService = new MemoryOtpService(generator, systemClock, authConfig);
    var mailSender = new DefaultMailSender();
    return new OtpMailFormAuthenticator(otpService, credentialService, mailSender);
  }

  @Override
  public void init(Config.Scope config) {
    // unused
  }

  @Override
  public void postInit(KeycloakSessionFactory factory) {
    // unused
  }

  @Override
  public void close() {
    // unused
  }
}
