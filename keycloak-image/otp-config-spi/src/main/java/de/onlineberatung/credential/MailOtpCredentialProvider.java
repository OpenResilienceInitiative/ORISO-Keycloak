package de.onlineberatung.credential;

import de.onlineberatung.authenticator.OtpMailAuthenticator;
import java.time.Clock;
import org.jboss.logging.Logger;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.CredentialTypeMetadata;
import org.keycloak.credential.CredentialTypeMetadataContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;

public class MailOtpCredentialProvider implements CredentialProvider<MailOtpCredentialModel>,
    CredentialInputValidator {

  private static final Logger logger = Logger.getLogger(MailOtpCredentialProvider.class);

  private final KeycloakSession session;
  private final Clock clock;

  public MailOtpCredentialProvider(KeycloakSession session, Clock clock) {
    this.session = session;
    this.clock = clock;
  }

  @Override
  public String getType() {
    return MailOtpCredentialModel.TYPE;
  }

  @Override
  public CredentialModel createCredential(RealmModel realm, UserModel user,
      MailOtpCredentialModel credentialModel) {
    if (credentialModel.getCreatedDate() == null) {
      credentialModel.setCreatedDate(clock.millis());
    }
    return user.credentialManager().createStoredCredential(credentialModel);
  }

  @Override
  public boolean deleteCredential(RealmModel realm, UserModel user, String credentialId) {
    return user.credentialManager().removeStoredCredentialById(credentialId);
  }

  @Override
  public MailOtpCredentialModel getCredentialFromModel(CredentialModel model) {
    return MailOtpCredentialModel.createFromCredentialModel(model);
  }

  @Override
  public CredentialTypeMetadata getCredentialTypeMetadata(
      CredentialTypeMetadataContext metadataContext) {
    return CredentialTypeMetadata.builder()
        .type(getType())
        .category(CredentialTypeMetadata.Category.TWO_FACTOR)
        .displayName(MailOtpCredentialProviderFactory.PROVIDER_ID)
        .helpText("create email otp")
        .createAction(OtpMailAuthenticator.AUTHENTICATOR_ID)
        .removeable(false)
        .build(session);
  }

  @Override
  public boolean supportsCredentialType(String credentialType) {
    return getType().equals(credentialType);
  }

  @Override
  public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
    if (!supportsCredentialType(credentialType)) {
      return false;
    }
    return user.credentialManager().getStoredCredentialsByTypeStream(credentialType)
        .findFirst().isPresent();
  }

  @Override
  public boolean isValid(RealmModel realm, UserModel user, CredentialInput credentialInput) {
    if (!(credentialInput instanceof UserCredentialModel)) {
      logger.debug("Expected instance of UserCredentialModel for CredentialInput");
      return false;
    }
    if (!credentialInput.getType().equals(getType())) {
      return false;
    }
    String challengeResponse = credentialInput.getChallengeResponse();
    if (challengeResponse == null) {
      return false;
    }
    var credentialModel = user.credentialManager()
        .getStoredCredentialById(credentialInput.getCredentialId());
    var otpCredentialModel = getCredentialFromModel(credentialModel);
    return otpCredentialModel.getOtp().getCode().equals(challengeResponse);
  }

  public void updateCredential(UserModel user, MailOtpCredentialModel credentialModel) {
    user.credentialManager().updateStoredCredential(credentialModel);
  }
}
