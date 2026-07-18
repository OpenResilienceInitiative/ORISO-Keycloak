package de.onlineberatung.credential;

import java.time.Clock;
import org.keycloak.credential.CredentialProviderFactory;
import org.keycloak.models.KeycloakSession;

public class MailOtpCredentialProviderFactory implements
    CredentialProviderFactory<MailOtpCredentialProvider> {

  public static final String PROVIDER_ID = "MAIL_OTP";

  @Override
  public MailOtpCredentialProvider create(KeycloakSession session) {
    return new MailOtpCredentialProvider(session, Clock.systemDefaultZone());
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }
}
