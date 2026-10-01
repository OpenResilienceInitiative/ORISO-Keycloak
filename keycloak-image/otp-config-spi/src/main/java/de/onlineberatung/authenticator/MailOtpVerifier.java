package de.onlineberatung.authenticator;

import static java.util.Objects.isNull;

import de.onlineberatung.credential.CredentialContext;
import de.onlineberatung.credential.MailOtpCredentialModel;
import de.onlineberatung.credential.MailOtpCredentialService;
import de.onlineberatung.otp.OtpService;
import de.onlineberatung.otp.ValidationResult;

/**
 * Decides whether a submitted e-mail code is good, and does the bookkeeping that follows.
 *
 * <p>Two authenticators ask this question: the direct-grant one answers a token request with JSON,
 * the browser one answers with a form. Only the answer differs. "A wrong code counts against the
 * attempt limit" and "a correct code burns the credential" live here so they cannot become two
 * implementations that disagree — an attempt limit that only one of two login paths enforces is
 * not an attempt limit.
 */
public class MailOtpVerifier {

  private final OtpService otpService;
  private final MailOtpCredentialService credentialService;

  public MailOtpVerifier(OtpService otpService, MailOtpCredentialService credentialService) {
    this.otpService = otpService;
    this.credentialService = credentialService;
  }

  /**
   * @param submittedCode what the user typed
   * @param credentialModel the stored code, or null when the user has none
   * @return the verdict; {@code NOT_PRESENT} when there is nothing to check against
   */
  public ValidationResult verify(String submittedCode, MailOtpCredentialModel credentialModel,
      CredentialContext context) {
    if (isNull(credentialModel)) {
      return ValidationResult.NOT_PRESENT;
    }

    var otp = credentialModel.getOtp();
    var result = otpService.validate(submittedCode, otp);

    switch (result) {
      case VALID:
        credentialService.invalidate(credentialModel, context);
        break;
      case INVALID:
        credentialService.incrementFailedAttempts(credentialModel, context,
            otp.getFailedVerifications());
        break;
      default:
        // EXPIRED is the clock's doing, not the user's, so it must not count against
        // them; TOO_MANY_FAILED_ATTEMPTS has already been counted; NOT_PRESENT has
        // nothing to count.
        break;
    }

    return result;
  }
}
