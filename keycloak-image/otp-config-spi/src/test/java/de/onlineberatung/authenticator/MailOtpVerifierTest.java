package de.onlineberatung.authenticator;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import de.onlineberatung.credential.CredentialContext;
import de.onlineberatung.credential.MailOtpCredentialModel;
import de.onlineberatung.credential.MailOtpCredentialService;
import de.onlineberatung.otp.Otp;
import de.onlineberatung.otp.OtpFailureLockout;
import de.onlineberatung.otp.OtpService;
import de.onlineberatung.otp.ValidationResult;
import java.time.Clock;
import java.util.List;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * The verdict on a submitted e-mail code, and the bookkeeping that goes with it, belong in one
 * place: the direct-grant authenticator answers a token request with JSON and the browser one
 * answers with a form, but "a wrong code counts against the attempt limit" and "a correct code
 * burns the credential" must not be two implementations that can disagree.
 */
public class MailOtpVerifierTest {

  private static final int MAX_FAILED = 3;

  private OtpService otpService;
  private MailOtpCredentialService credentialService;
  private CredentialContext credentialContext;
  private MailOtpCredentialModel credential;
  private MailOtpVerifier verifier;

  @Before
  public void setUp() {
    otpService = mock(OtpService.class);
    when(otpService.maxFailedValidations()).thenReturn(MAX_FAILED);
    credentialService = mock(MailOtpCredentialService.class);
    credentialContext =
        new CredentialContext(
            mock(KeycloakSession.class), mock(RealmModel.class), mock(UserModel.class));
    credential = credentialWithFailures(1);
    verifier =
        new MailOtpVerifier(
            otpService,
            credentialService,
            new OtpFailureLockout(Clock.systemDefaultZone(), List.of(60L, 1440L), 86400));
  }

  private static MailOtpCredentialModel credentialWithFailures(int failures) {
    return MailOtpCredentialModel.createOtpModel(
        new Otp("1234", 300, 1000L, "counsellor@example.org", failures),
        Clock.systemDefaultZone());
  }

  private MailOtpVerifier.Verdict verifyWith(ValidationResult serviceVerdict) {
    when(otpService.validate(eq("1234"), any(Otp.class))).thenReturn(serviceVerdict);
    return verifier.verify("1234", credential, credentialContext);
  }

  @Test
  public void verify_should_burn_the_credential_when_the_code_is_valid() {
    var verdict = verifyWith(ValidationResult.VALID);

    assertThat(verdict.getResult()).isEqualTo(ValidationResult.VALID);
    // acceptCode and not invalidate: a correct code also clears the lockout ladder,
    // while a failed mail (which also invalidates) must not.
    verify(credentialService).acceptCode(credential, credentialContext);
  }

  @Test
  public void verify_should_count_a_wrong_code_against_the_attempt_limit() {
    var verdict = verifyWith(ValidationResult.INVALID);

    assertThat(verdict.getResult()).isEqualTo(ValidationResult.INVALID);
    assertThat(verdict.getRetryInSeconds()).isZero();
    verify(credentialService).incrementFailedAttempts(credential, credentialContext, 1);
    verify(credentialService, never()).lockOut(any(), any(), any());
  }

  @Test
  public void verify_should_lock_out_on_the_last_wrong_code_rather_than_one_attempt_later() {
    // The submission in between is where a resend would hand out a new code with a fresh
    // attempt counter, which is exactly the hole the lockout closes.
    credential = credentialWithFailures(MAX_FAILED - 1);

    var verdict = verifyWith(ValidationResult.INVALID);

    assertThat(verdict.getResult()).isEqualTo(ValidationResult.TOO_MANY_FAILED_ATTEMPTS);
    assertThat(verdict.getRetryInSeconds()).isEqualTo(60);
    verify(credentialService).lockOut(eq(credential), eq(credentialContext), any());
    verify(credentialService, never()).incrementFailedAttempts(any(), any(), anyInt());
  }

  @Test
  public void verify_should_not_count_an_expired_code_against_the_attempt_limit() {
    // Expiry is the clock's doing, not the user's; charging them for it would lock
    // an account out over a slow mail server.
    var verdict = verifyWith(ValidationResult.EXPIRED);

    assertThat(verdict.getResult()).isEqualTo(ValidationResult.EXPIRED);
    verify(credentialService, never()).incrementFailedAttempts(any(), any(), anyInt());
    verify(credentialService, never()).acceptCode(any(), any());
    verify(credentialService, never()).lockOut(any(), any(), any());
  }

  @Test
  public void verify_should_start_a_lockout_for_a_credential_that_is_already_past_the_limit() {
    // Written by an older image: at the limit, but with no lockout stored. Without this it
    // would refuse every code forever, because nothing would ever reset the counter.
    var verdict = verifyWith(ValidationResult.TOO_MANY_FAILED_ATTEMPTS);

    assertThat(verdict.getResult()).isEqualTo(ValidationResult.TOO_MANY_FAILED_ATTEMPTS);
    assertThat(verdict.getRetryInSeconds()).isEqualTo(60);
    verify(credentialService).lockOut(eq(credential), eq(credentialContext), any());
  }

  @Test
  public void verify_should_report_a_missing_credential_without_touching_the_service() {
    var verdict = verifier.verify("1234", null, credentialContext);

    assertThat(verdict.getResult()).isEqualTo(ValidationResult.NOT_PRESENT);
    verifyNoInteractions(otpService);
    verifyNoInteractions(credentialService);
  }
}
