package de.onlineberatung;

import static de.onlineberatung.authenticator.OtpMailAuthenticatorFactory.OTP_CONFIG_ALIAS;

import de.onlineberatung.authenticator.BearerTokenSessionAuthenticator;
import de.onlineberatung.credential.AppOtpCredentialService;
import de.onlineberatung.credential.MailOtpCredentialProviderFactory;
import de.onlineberatung.credential.MailOtpCredentialService;
import de.onlineberatung.mail.DefaultMailSender;
import de.onlineberatung.otp.MemoryOtpService;
import de.onlineberatung.otp.RandomDigitsCodeGenerator;
import java.time.Clock;
import org.keycloak.Config.Scope;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

public class RealmOtpResourceProviderFactory implements RealmResourceProviderFactory {

  public static final String ID = "otp-config";

  @Override
  public RealmResourceProvider create(KeycloakSession keycloakSession) {
    var systemClock = Clock.systemDefaultZone();
    var otpGenerator = new RandomDigitsCodeGenerator();
    var mailSender = new DefaultMailSender();
    var authConfig = keycloakSession.getContext().getRealm()
        .getAuthenticatorConfigByAlias(OTP_CONFIG_ALIAS);
    var otpMailService = new MemoryOtpService(otpGenerator, systemClock, authConfig);
    var mailOtpCredentialProvider = new MailOtpCredentialProviderFactory().create(keycloakSession);
    var mailOtpCredentialService = new MailOtpCredentialService(mailOtpCredentialProvider,
        systemClock);
    var appCredentialService = new AppOtpCredentialService();
    return new RealmOtpResourceProvider(keycloakSession, otpMailService, mailSender,
        new BearerTokenSessionAuthenticator(), appCredentialService, mailOtpCredentialService);
  }

  @Override
  public void init(Scope scope) {
    // Do nothing because it is not needed
  }

  @Override
  public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
    // Do nothing because it is not needed
  }

  @Override
  public void close() {
    // Do nothing because it is not needed
  }

  @Override
  public String getId() {
    return ID;
  }
}
