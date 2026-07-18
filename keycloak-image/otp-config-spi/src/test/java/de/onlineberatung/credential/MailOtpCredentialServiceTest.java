package de.onlineberatung.credential;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import de.onlineberatung.otp.Otp;
import java.time.Clock;
import org.assertj.core.api.AssertionsForClassTypes;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.mockito.stubbing.Answer;

public class MailOtpCredentialServiceTest {

  private MailOtpCredentialService credentialService;
  private UserModel user;
  private CredentialContext credentialContext;
  private MailOtpCredentialProvider credentialProvider;

  @Before
  public void setUp() {
    RealmModel realm = mock(RealmModel.class);
    KeycloakSession session = mock(KeycloakSession.class);
    user = mock(UserModel.class);
    credentialContext = new CredentialContext(session, realm, user);
    credentialProvider = mock(MailOtpCredentialProvider.class);
    when(credentialProvider.createCredential(eq(realm), eq(user), any())).thenAnswer(
        (Answer<MailOtpCredentialModel>) invocation -> {
          Object[] args = invocation.getArguments();
          return (MailOtpCredentialModel) args[2];
        });
    credentialService = new MailOtpCredentialService(credentialProvider, Clock.systemDefaultZone());
  }

  @Test
  public void activate_should_activate_and_reset_failed_verifications() {
    var otp = new Otp("1234", 30, 1233124L, "test@mail.com", 2);
    var credential = credentialService.createCredential(otp, credentialContext);
    assertThat(credential.isActive()).isFalse();

    credentialService.activate(credential, credentialContext);

    assertThat(credential.isActive()).isTrue();
    AssertionsForClassTypes.assertThat(credential.getOtp().getFailedVerifications()).isZero();
    AssertionsForClassTypes
        .assertThat(credential.getOtp().getCode()).isEqualTo(MailOtpCredentialModel.INVALIDATED);
    verify(credentialProvider).updateCredential(user, credential);
  }

  @Test
  public void invalidate_should_invalidate_code_and_reset_failed_verifications() {
    var otp = new Otp("1234", 30, 1233124L, "test@mail.com", 2);
    var credential = credentialService.createCredential(otp, credentialContext);

    credentialService.invalidate(credential, credentialContext);

    AssertionsForClassTypes.assertThat(credential.getOtp().getFailedVerifications()).isZero();
    AssertionsForClassTypes
        .assertThat(credential.getOtp().getCode()).isEqualTo(MailOtpCredentialModel.INVALIDATED);
    verify(credentialProvider).updateCredential(user, credential);
  }

  @Test
  public void incrementFailedAttempts_should_increment_failed_attempts() {
    var otp = new Otp("1234", 30, 1233124L, "test@mail.com", 0);
    var credential = credentialService.createCredential(otp, credentialContext);

    credentialService.incrementFailedAttempts(credential, credentialContext,
        otp.getFailedVerifications());

    AssertionsForClassTypes.assertThat(credential.getOtp().getFailedVerifications()).isEqualTo(1);
    verify(credentialProvider).updateCredential(user, credential);
  }
}
