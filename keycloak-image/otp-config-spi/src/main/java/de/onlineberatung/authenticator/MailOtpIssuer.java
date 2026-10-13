package de.onlineberatung.authenticator;

import static java.util.Objects.isNull;

import de.onlineberatung.credential.CredentialContext;
import de.onlineberatung.credential.MailOtpCredentialModel;
import de.onlineberatung.credential.MailOtpCredentialService;
import de.onlineberatung.mail.MailSendingException;
import de.onlineberatung.otp.OtpMailSender;
import de.onlineberatung.otp.OtpMailThrottle;
import de.onlineberatung.otp.OtpService;
import java.util.List;
import org.jboss.logging.Logger;

/**
 * Mails a new e-mail code, or explains why it does not (#1338).
 *
 * <p>Shared by the direct-grant and the browser authenticator for the same reason as {@link
 * MailOtpVerifier}: a cooldown or a mail cap that only one of two login paths honours is no brake,
 * because the other path is one URL away. Only the shape of the answer differs between them.
 *
 * <p>A new code replaces the old one ("only the newest code is valid") and starts with a fresh
 * attempt counter. Inside the cooldown nothing is replaced, so a resend request can no longer reset
 * the counter of the code the user already has.
 */
public class MailOtpIssuer {

  private static final Logger logger = Logger.getLogger(MailOtpIssuer.class);

  private final OtpService otpService;
  private final MailOtpCredentialService credentialService;
  private final OtpMailSender mailSender;
  private final OtpMailThrottle throttle;

  public MailOtpIssuer(OtpService otpService, MailOtpCredentialService credentialService,
      OtpMailSender mailSender, OtpMailThrottle throttle) {
    this.otpService = otpService;
    this.credentialService = credentialService;
    this.mailSender = mailSender;
    this.throttle = throttle;
  }

  public Outcome issue(MailOtpCredentialModel credentialModel, CredentialContext credContext) {
    var previousHistory = credentialModel.getMailsSentAt();
    var decision = throttle.decide(previousHistory, credentialModel.hasLiveCode(throttle.clock()));

    switch (decision.getVerdict()) {
      case WAIT:
        return new Outcome(Result.KEPT, decision.getRetryInSeconds());
      case LIMIT_REACHED:
        logger.info("e-mail code for keycloak user " + credContext.getUser().getId()
            + " not sent: mail cap reached");
        return new Outcome(Result.LIMIT_REACHED, decision.getRetryInSeconds());
      default:
        return send(credentialModel, credContext, previousHistory);
    }
  }

  private Outcome send(MailOtpCredentialModel credentialModel, CredentialContext credContext,
      List<Long> previousHistory) {
    var emailAddress = credContext.getUser().getEmail();
    if (isNull(emailAddress) || emailAddress.isBlank()) {
      logger.warn("keycloak user with id " + credContext.getUser().getId()
          + " has no email configured. Will use address from credentials instead");
      emailAddress = credentialModel.getOtp().getEmail();
    }

    var otp = otpService.createOtp(emailAddress);
    var history = throttle.recordMail(previousHistory);
    credentialService.update(credentialModel.updateFrom(otp, history), credContext);

    try {
      mailSender.sendOtpCode(otp, credContext);
      return new Outcome(Result.SENT, throttle.secondsUntilNextMail(history));
    } catch (MailSendingException e) {
      // The stored code was already rotated to one nobody received; leaving it live would
      // make the next attempt fail against a code that exists only here. No mail went out,
      // so it must not count towards the cooldown or the cap either.
      credentialModel.restoreMailsSentAt(previousHistory);
      credentialService.invalidate(credentialModel, credContext);
      logger.error("failed to send otp mail", e);
      return new Outcome(Result.MAIL_FAILED, 0);
    }
  }

  public enum Result {
    /** A new code was mailed. */
    SENT,
    /** Inside the cooldown: nothing mailed, the last code stays valid. */
    KEPT,
    /** The mail cap is used up: nothing mailed. */
    LIMIT_REACHED,
    /** Sending failed; the stored code was invalidated. */
    MAIL_FAILED
  }

  public static final class Outcome {

    private final Result result;
    private final long resendAvailableInSeconds;

    Outcome(Result result, long resendAvailableInSeconds) {
      this.result = result;
      this.resendAvailableInSeconds = resendAvailableInSeconds;
    }

    public Result getResult() {
      return result;
    }

    /** Seconds until a request without a code will mail a new one. */
    public long getResendAvailableInSeconds() {
      return resendAvailableInSeconds;
    }
  }
}
