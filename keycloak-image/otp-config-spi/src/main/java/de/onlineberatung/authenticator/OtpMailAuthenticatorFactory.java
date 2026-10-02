package de.onlineberatung.authenticator;

import static java.util.Arrays.asList;

import de.onlineberatung.credential.MailOtpCredentialProviderFactory;
import de.onlineberatung.credential.MailOtpCredentialService;
import de.onlineberatung.mail.DefaultMailSender;
import de.onlineberatung.otp.MailOtpSendPolicy;
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

public class OtpMailAuthenticatorFactory implements AuthenticatorFactory {

  public static final String OTP_CONFIG_ALIAS = "email-otp-config";

  @Override
  public String getId() {
    return OtpMailAuthenticator.AUTHENTICATOR_ID;
  }

  @Override
  public String getDisplayType() {
    return "Email Authentication";
  }

  @Override
  public String getHelpText() {
    return "Validates an OTP sent via email to the users email address.";
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
            ProviderConfigProperty.BOOLEAN_TYPE, true),
        // #1338: the brake on code mails. Settings rather than constants so the thresholds can be
        // corrected in the admin console without cutting a new image.
        new ProviderConfigProperty(MailOtpSendPolicy.COOLDOWN_CONFIG_KEY, "Resend cooldown",
            "Seconds after a code mail in which no further mail is sent. The code already sent "
                + "stays valid.", ProviderConfigProperty.STRING_TYPE,
            String.valueOf(MailOtpSendPolicy.DEFAULT_COOLDOWN_SECONDS)),
        new ProviderConfigProperty(MailOtpSendPolicy.MAX_SENDS_CONFIG_KEY, "Max code mails",
            "Maximum number of code mails per user within the send window. Further requests are "
                + "answered with 429 and send nothing.", ProviderConfigProperty.STRING_TYPE,
            String.valueOf(MailOtpSendPolicy.DEFAULT_MAX_SENDS_PER_WINDOW)),
        new ProviderConfigProperty(MailOtpSendPolicy.WINDOW_CONFIG_KEY, "Send window",
            "Length of the rolling window for the maximum above, in seconds.",
            ProviderConfigProperty.STRING_TYPE,
            String.valueOf(MailOtpSendPolicy.DEFAULT_WINDOW_SECONDS))
    );
  }

  @Override
  public Authenticator create(KeycloakSession session) {
    var authConfig = session.getContext().getRealm()
        .getAuthenticatorConfigByAlias(OTP_CONFIG_ALIAS);
    var generator = new RandomDigitsCodeGenerator();
    var systemClock = Clock.systemDefaultZone();
    var mailOtpCredentialProvider = new MailOtpCredentialProviderFactory().create(session);
    var credentialService = new MailOtpCredentialService(mailOtpCredentialProvider, systemClock);
    var otpService = new MemoryOtpService(generator, systemClock, authConfig);
    var mailSender = new DefaultMailSender();
    var sendPolicy = new MailOtpSendPolicy(systemClock, authConfig);
    return new OtpMailAuthenticator(otpService, credentialService, mailSender, sendPolicy);
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
