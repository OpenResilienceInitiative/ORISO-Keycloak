package de.onlineberatung.credential;

import static java.util.Objects.isNull;
import static java.util.Objects.nonNull;

import de.onlineberatung.otp.Otp;
import java.time.Clock;

public class MailOtpCredentialService {

  private final MailOtpCredentialProvider credentialProvider;
  private final Clock clock;

  public MailOtpCredentialService(MailOtpCredentialProvider credentialProvider, Clock clock) {
    this.credentialProvider = credentialProvider;
    this.clock = clock;
  }

  public MailOtpCredentialModel createCredential(Otp otp, CredentialContext context) {
    var credentialModel = MailOtpCredentialModel.createOtpModel(otp, clock, false);
    var storedCredentialModel = credentialProvider.createCredential(context.getRealm(),
        context.getUser(),
        credentialModel);
    // create from stored credential model to get the ID
    return MailOtpCredentialModel.createFromCredentialModel(storedCredentialModel);
  }

  public void update(MailOtpCredentialModel credentialModel, CredentialContext context) {
    credentialProvider.updateCredential(context.getUser(), credentialModel);
  }

  public void incrementFailedAttempts(MailOtpCredentialModel credentialModel,
      CredentialContext context, int currentAttempts) {
    credentialModel.updateFailedVerifications(currentAttempts + 1);
    credentialModel.updateInternalModel();
    credentialProvider.updateCredential(context.getUser(), credentialModel);
  }

  public void activate(MailOtpCredentialModel credentialModel, CredentialContext context) {
    credentialModel.setActive();
    credentialModel.updateFailedVerifications(0);
    credentialModel.invalidateCode();
    credentialModel.updateInternalModel();
    credentialProvider.updateCredential(context.getUser(), credentialModel);
  }

  public MailOtpCredentialModel getCredential(CredentialContext context) {
    return credentialProvider.getDefaultCredential(context.getSession(), context.getRealm(),
        context.getUser());
  }

  public void deleteCredential(CredentialContext context) {
    var credential = getCredential(context);
    if (isNull(credential)) {
      return;
    }
    credentialProvider.deleteCredential(context.getRealm(), context.getUser(), credential.getId());
  }

  public void invalidate(MailOtpCredentialModel credentialModel, CredentialContext context) {
    credentialModel.updateFailedVerifications(0);
    credentialModel.invalidateCode();
    credentialModel.updateInternalModel();
    credentialProvider.updateCredential(context.getUser(), credentialModel);
  }

  public boolean is2FAConfigured(CredentialContext context) {
    var credential = getCredential(context);
    return nonNull(credential) && credential.isActive();
  }
}
