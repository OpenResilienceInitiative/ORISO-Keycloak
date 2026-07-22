package de.onlineberatung.credential;

import static java.util.Objects.nonNull;

import de.onlineberatung.otp.Otp;
import java.time.Clock;
import java.util.List;
import java.util.stream.Collectors;

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

  public List<MailOtpCredentialModel> getAllCredentials(CredentialContext context) {
    return context.getUser().credentialManager()
        .getStoredCredentialsByTypeStream(MailOtpCredentialModel.TYPE)
        .map(MailOtpCredentialModel::createFromCredentialModel)
        .collect(Collectors.toList());
  }

  public void deleteCredential(CredentialContext context) {
    var credentials = getAllCredentials(context);
    for (var credential : credentials) {
      credentialProvider.deleteCredential(context.getRealm(), context.getUser(),
          credential.getId());
    }
  }

  public void deleteInactiveCredentials(CredentialContext context) {
    var credentials = getAllCredentials(context);
    for (var credential : credentials) {
      if (!credential.isActive()) {
        credentialProvider.deleteCredential(context.getRealm(), context.getUser(),
            credential.getId());
      }
    }
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
