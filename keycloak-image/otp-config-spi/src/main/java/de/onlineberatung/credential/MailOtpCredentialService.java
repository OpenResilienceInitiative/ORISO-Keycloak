package de.onlineberatung.credential;

import static java.util.Objects.nonNull;

import de.onlineberatung.otp.Otp;
import de.onlineberatung.otp.OtpFailureLockout;
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
    credentialModel.clearLockout();
    credentialModel.updateInternalModel();
    credentialProvider.updateCredential(context.getUser(), credentialModel);
  }

  /**
   * Starts the failed-attempt lockout, or escalates it to the next step of the ladder.
   *
   * <p>The spent code goes with it: leaving it live would let the guessing continue the moment
   * the lockout ends, against a code the attacker has already had a day to work on. The attempt
   * counter is cleared at the same time, so the next code starts with its full three attempts
   * rather than being refused for a limit that was already paid for with a lockout.
   */
  public void lockOut(MailOtpCredentialModel credentialModel, CredentialContext context,
      OtpFailureLockout.Lock lock) {
    credentialModel.lockOut(lock.getLockedUntil(), lock.getLevel());
    credentialModel.updateFailedVerifications(0);
    credentialModel.invalidateCode();
    credentialModel.updateInternalModel();
    credentialProvider.updateCredential(context.getUser(), credentialModel);
  }

  /**
   * The code was right: burn it and clear the lockout ladder.
   *
   * <p>Separate from {@link #invalidate} because that one also runs when a mail could not be
   * sent, and a failed mail must not be a way out of a lockout.
   */
  public void acceptCode(MailOtpCredentialModel credentialModel, CredentialContext context) {
    credentialModel.updateFailedVerifications(0);
    credentialModel.invalidateCode();
    credentialModel.clearLockout();
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

  public void deleteById(CredentialContext context, String credentialId) {
    credentialProvider.deleteCredential(context.getRealm(), context.getUser(), credentialId);
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
