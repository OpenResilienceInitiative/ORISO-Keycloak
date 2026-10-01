package de.onlineberatung.authenticator;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.any;
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
import de.onlineberatung.otp.OtpService;
import de.onlineberatung.otp.ValidationResult;
import java.time.Clock;
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

  private OtpService otpService;
  private MailOtpCredentialService credentialService;
  private CredentialContext credentialContext;
  private MailOtpCredentialModel credential;
  private MailOtpVerifier verifier;

  @Before
  public void setUp() {
    otpService = mock(OtpService.class);
    credentialService = mock(MailOtpCredentialService.class);
    credentialContext =
        new CredentialContext(
            mock(KeycloakSession.class), mock(RealmModel.class), mock(UserModel.class));
    credential =
        MailOtpCredentialModel.createOtpModel(
            new Otp("1234", 300, 1000L, "counsellor@example.org", 2), Clock.systemDefaultZone());
    verifier = new MailOtpVerifier(otpService, credentialService);
  }

  private ValidationResult verifyWith(ValidationResult serviceVerdict) {
    when(otpService.validate(eq("1234"), any(Otp.class))).thenReturn(serviceVerdict);
    return verifier.verify("1234", credential, credentialContext);
  }

  @Test
  public void verify_should_burn_the_credential_when_the_code_is_valid() {
    var result = verifyWith(ValidationResult.VALID);

    assertThat(result).isEqualTo(ValidationResult.VALID);
    verify(credentialService).invalidate(credential, credentialContext);
  }

  @Test
  public void verify_should_count_a_wrong_code_against_the_attempt_limit() {
    var result = verifyWith(ValidationResult.INVALID);

    assertThat(result).isEqualTo(ValidationResult.INVALID);
    verify(credentialService).incrementFailedAttempts(credential, credentialContext, 2);
  }

  @Test
  public void verify_should_not_count_an_expired_code_against_the_attempt_limit() {
    // Expiry is the clock's doing, not the user's; charging them for it would lock
    // an account out over a slow mail server.
    var result = verifyWith(ValidationResult.EXPIRED);

    assertThat(result).isEqualTo(ValidationResult.EXPIRED);
    verify(credentialService, never())
        .incrementFailedAttempts(any(), any(), org.mockito.ArgumentMatchers.anyInt());
    verify(credentialService, never()).invalidate(any(), any());
  }

  @Test
  public void verify_should_pass_through_the_attempt_limit_verdict_untouched() {
    var result = verifyWith(ValidationResult.TOO_MANY_FAILED_ATTEMPTS);

    assertThat(result).isEqualTo(ValidationResult.TOO_MANY_FAILED_ATTEMPTS);
    verify(credentialService, never())
        .incrementFailedAttempts(any(), any(), org.mockito.ArgumentMatchers.anyInt());
  }

  @Test
  public void verify_should_report_a_missing_credential_without_touching_the_service() {
    var result = verifier.verify("1234", null, credentialContext);

    assertThat(result).isEqualTo(ValidationResult.NOT_PRESENT);
    verifyNoInteractions(otpService);
    verifyNoInteractions(credentialService);
  }
}
