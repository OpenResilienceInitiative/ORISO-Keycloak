package de.onlineberatung.authenticator;

import static java.util.Objects.isNull;

import de.onlineberatung.credential.CredentialContext;
import de.onlineberatung.credential.MailOtpCredentialModel;
import de.onlineberatung.credential.MailOtpCredentialService;
import de.onlineberatung.otp.OtpFailureLockout;
import de.onlineberatung.otp.OtpService;
import de.onlineberatung.otp.ValidationResult;
import java.time.Clock;

/**
 * Decides whether a submitted e-mail code is good, and does the bookkeeping that follows.
 *
 * <p>Two authenticators ask this question: the direct-grant one answers a token request with JSON,
 * the browser one answers with a form. Only the answer differs. "A wrong code counts against the
 * attempt limit" and "a correct code burns the credential" live here so they cannot become two
 * implementations that disagree — an attempt limit that only one of two login paths enforces is
 * not an attempt limit.
 *
 * <p>The attempt limit now starts an escalating lockout ({@link OtpFailureLockout}), so the verdict
 * carries the remaining wait and not only the fact of the refusal.
 */
public class MailOtpVerifier {

  private final OtpService otpService;
  private final MailOtpCredentialService credentialService;
  private final OtpFailureLockout lockout;

  /** Lockout at its defaults; kept for callers that do not configure one. */
  public MailOtpVerifier(OtpService otpService, MailOtpCredentialService credentialService) {
    this(otpService, credentialService,
        OtpFailureLockout.fromConfig(Clock.systemDefaultZone(), null));
  }

  public MailOtpVerifier(OtpService otpService, MailOtpCredentialService credentialService,
      OtpFailureLockout lockout) {
    this.otpService = otpService;
    this.credentialService = credentialService;
    this.lockout = lockout;
  }

  /**
   * @param submittedCode what the user typed
   * @param credentialModel the stored code, or null when the user has none
   * @return the verdict; {@code NOT_PRESENT} when there is nothing to check against
   */
  public Verdict verify(String submittedCode, MailOtpCredentialModel credentialModel,
      CredentialContext context) {
    if (isNull(credentialModel)) {
      return new Verdict(ValidationResult.NOT_PRESENT, 0);
    }

    // Checked before the code: a lockout that could still be probed for a correct code would
    // be a hint generator, and every probe would have to be counted somewhere.
    var standing = lockout.decide(credentialModel.getLockedUntil());
    if (standing.isLocked()) {
      return new Verdict(ValidationResult.TOO_MANY_FAILED_ATTEMPTS, standing.getRetryInSeconds());
    }

    var otp = credentialModel.getOtp();
    var result = otpService.validate(submittedCode, otp);

    switch (result) {
      case VALID:
        credentialService.acceptCode(credentialModel, context);
        break;
      case INVALID:
        var failures = otp.getFailedVerifications() + 1;
        if (failures >= otpService.maxFailedValidations()) {
          // This wrong code was the last one. Locking here and not on the next submission is
          // the point: in between, a resend would hand out a new code with fresh attempts.
          return new Verdict(ValidationResult.TOO_MANY_FAILED_ATTEMPTS,
              startLockout(credentialModel, context));
        }
        credentialService.incrementFailedAttempts(credentialModel, context,
            otp.getFailedVerifications());
        break;
      case TOO_MANY_FAILED_ATTEMPTS:
        // A credential that reached the limit before this version existed, so no lockout was
        // ever stored for it. Start one now rather than leaving it refusing forever.
        return new Verdict(result, startLockout(credentialModel, context));
      default:
        // EXPIRED is the clock's doing, not the user's, so it must not count against
        // them; NOT_PRESENT has nothing to count.
        break;
    }

    return new Verdict(result, 0);
  }

  private long startLockout(MailOtpCredentialModel credentialModel, CredentialContext context) {
    var lock = lockout.escalate(credentialModel.getLockedUntil(),
        credentialModel.getLockoutLevel());
    credentialService.lockOut(credentialModel, context, lock);
    return lock.getWaitSeconds();
  }

  /** The verdict plus, for a refusal that has a duration, how long it lasts. */
  public static final class Verdict {

    private final ValidationResult result;
    private final long retryInSeconds;

    Verdict(ValidationResult result, long retryInSeconds) {
      this.result = result;
      this.retryInSeconds = retryInSeconds;
    }

    public ValidationResult getResult() {
      return result;
    }

    /** Seconds until a code is accepted again; 0 when the refusal has no duration. */
    public long getRetryInSeconds() {
      return retryInSeconds;
    }
  }
}
