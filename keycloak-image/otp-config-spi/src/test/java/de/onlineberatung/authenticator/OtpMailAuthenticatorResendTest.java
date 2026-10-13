package de.onlineberatung.authenticator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import de.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.Challenge;
import de.onlineberatung.keycloak_otp_config_spi.keycloakextension.generated.web.model.OtpType;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.Response;
import java.util.Map;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.http.HttpRequest;
import org.keycloak.models.AuthenticatorConfigModel;

/**
 * The e-mail code on the direct grant (app and Admin panel login), seen from the token client.
 *
 * <p>Before #1338 every token request without a code mailed a fresh code and reset the
 * failed-attempt counter, so anyone holding the password got unlimited mails and unlimited
 * rounds of three guesses. These tests pin the brake: a cooldown between mails, a cap per
 * window, and a counter that a resend request cannot reset.
 */
public class OtpMailAuthenticatorResendTest {

  private MailOtpLoginFixture fx;
  private OtpMailAuthenticator authenticator;

  @Before
  public void setUp() {
    fx = new MailOtpLoginFixture();
    authenticator = new OtpMailAuthenticator(fx.otpService, fx.credentialService, fx.mailSender,
        fx.defaultThrottle());
  }

  @Test
  public void first_request_mails_a_code_and_announces_the_cooldown() {
    var answer = tokenRequest(null);

    assertThat(fx.mailedCodes).hasSize(1);
    assertThat(answer.status).isEqualTo(400);
    assertThat(answer.credentialFailure).isFalse();
    assertThat(answer.challenge.getOtpType()).isEqualTo(OtpType.EMAIL);
    assertThat(answer.challenge.getError()).isEqualTo("invalid_grant");
    assertThat(answer.challenge.getErrorDescription()).isEqualTo("Missing totp");
    assertThat(answer.challenge.getResendAvailableInSeconds()).isEqualTo(30);
  }

  @Test
  public void a_second_request_within_the_cooldown_sends_no_mail_and_keeps_the_first_code() {
    tokenRequest(null);
    var firstCode = fx.lastMailedCode();

    fx.clock.advanceSeconds(10);
    var answer = tokenRequest(null);

    assertThat(fx.mailedCodes).hasSize(1);
    assertThat(answer.status).isEqualTo(400);
    assertThat(answer.credentialFailure).isFalse();
    assertThat(answer.challenge.getOtpType()).isEqualTo(OtpType.EMAIL);
    assertThat(answer.challenge.getResendAvailableInSeconds()).isEqualTo(20);

    assertThat(tokenRequest(firstCode).succeeded).isTrue();
  }

  @Test
  public void remaining_seconds_are_rounded_up_so_the_client_never_asks_too_early() {
    tokenRequest(null);

    fx.clock.advance(java.time.Duration.ofMillis(29_001));
    var answer = tokenRequest(null);

    assertThat(fx.mailedCodes).hasSize(1);
    assertThat(answer.challenge.getResendAvailableInSeconds()).isEqualTo(1);
  }

  @Test
  public void after_the_cooldown_a_new_code_is_mailed_and_only_the_newest_code_is_valid() {
    tokenRequest(null);
    var firstCode = fx.lastMailedCode();

    fx.clock.advanceSeconds(30);
    var answer = tokenRequest(null);

    assertThat(fx.mailedCodes).hasSize(2);
    assertThat(answer.status).isEqualTo(400);
    assertThat(answer.credentialFailure).isFalse();
    assertThat(answer.challenge.getResendAvailableInSeconds()).isEqualTo(30);
    var secondCode = fx.lastMailedCode();
    assertThat(secondCode).isNotEqualTo(firstCode);

    assertThat(tokenRequest(firstCode).status).isEqualTo(401);
    assertThat(tokenRequest(secondCode).succeeded).isTrue();
  }

  @Test
  public void the_sixth_mail_within_fifteen_minutes_is_refused_with_429_and_not_sent() {
    for (int i = 0; i < 5; i++) {
      tokenRequest(null);
      fx.clock.advanceSeconds(31);
    }
    assertThat(fx.mailedCodes).hasSize(5);
    // first mail at t=0, now t=155 s: the oldest mail leaves the window at t=900 s
    var answer = tokenRequest(null);

    assertThat(fx.mailedCodes).hasSize(5);
    assertThat(answer.status).isEqualTo(429);
    assertThat(answer.credentialFailure).isFalse();
    assertThat(answer.retryAfter).isEqualTo("745");
    assertThat(answer.challenge.getOtpType()).isEqualTo(OtpType.EMAIL);
    assertThat(answer.challenge.getResendAvailableInSeconds()).isEqualTo(745);
  }

  @Test
  public void the_last_permitted_mail_announces_when_the_cap_lets_the_next_one_through() {
    for (int i = 0; i < 4; i++) {
      tokenRequest(null);
      fx.clock.advanceSeconds(31);
    }
    // t=124 s, fifth mail: the next one is possible only when the first leaves the window
    var answer = tokenRequest(null);

    assertThat(fx.mailedCodes).hasSize(5);
    assertThat(answer.status).isEqualTo(400);
    assertThat(answer.credentialFailure).isFalse();
    assertThat(answer.challenge.getResendAvailableInSeconds()).isEqualTo(900 - 124);
  }

  @Test
  public void the_code_mailed_last_still_works_while_the_cap_refuses_more_mails() {
    for (int i = 0; i < 5; i++) {
      tokenRequest(null);
      fx.clock.advanceSeconds(31);
    }
    var lastCode = fx.lastMailedCode();
    tokenRequest(null);

    assertThat(tokenRequest(lastCode).succeeded).isTrue();
  }

  @Test
  public void the_window_slides_so_a_mail_is_allowed_again_once_the_oldest_leaves_it() {
    for (int i = 0; i < 5; i++) {
      tokenRequest(null);
      fx.clock.advanceSeconds(31);
    }
    fx.clock.advanceSeconds(900 - 155);

    var answer = tokenRequest(null);

    assertThat(fx.mailedCodes).hasSize(6);
    assertThat(answer.status).isEqualTo(400);
    assertThat(answer.credentialFailure).isFalse();
  }

  @Test
  public void a_resend_request_does_not_revive_a_code_after_three_wrong_guesses() {
    tokenRequest(null);
    var code = fx.lastMailedCode();
    for (int i = 0; i < 3; i++) {
      var wrongCode = tokenRequest("000000");
      assertThat(wrongCode.status).isEqualTo(401);
      assertThat(wrongCode.credentialFailure).isTrue();
    }
    assertThat(tokenRequest(code).status).isEqualTo(429);

    fx.clock.advanceSeconds(5);
    var resend = tokenRequest(null);

    assertThat(fx.mailedCodes).hasSize(1);
    assertThat(resend.challenge.getResendAvailableInSeconds()).isEqualTo(25);
    assertThat(tokenRequest(code).status).isEqualTo(429);
  }

  @Test
  public void a_permitted_resend_after_three_wrong_guesses_mails_a_code_that_works() {
    tokenRequest(null);
    var deadCode = fx.lastMailedCode();
    for (int i = 0; i < 3; i++) {
      tokenRequest("000000");
    }

    fx.clock.advanceSeconds(30);
    tokenRequest(null);

    assertThat(fx.mailedCodes).hasSize(2);
    assertThat(tokenRequest(deadCode).status).isEqualTo(401);
    assertThat(tokenRequest(fx.lastMailedCode()).succeeded).isTrue();
  }

  @Test
  public void a_failed_mail_does_not_start_the_cooldown() {
    fx.mailServerDown(true);
    var failedMail = tokenRequest(null);
    assertThat(failedMail.status).isEqualTo(500);
    assertThat(failedMail.credentialFailure).isFalse();

    fx.mailServerDown(false);
    var answer = tokenRequest(null);

    assertThat(fx.mailedCodes).hasSize(1);
    assertThat(answer.status).isEqualTo(400);
    assertThat(answer.credentialFailure).isFalse();
    assertThat(answer.challenge.getResendAvailableInSeconds()).isEqualTo(30);
  }

  @Test
  public void a_new_sign_in_right_after_a_successful_one_gets_a_fresh_code() {
    // The used code is burnt, so there is nothing the cooldown could protect; holding
    // the user back 30 s after a logout would only be in the way.
    tokenRequest(null);
    assertThat(tokenRequest(fx.lastMailedCode()).succeeded).isTrue();

    fx.clock.advanceSeconds(5);
    var answer = tokenRequest(null);

    assertThat(fx.mailedCodes).hasSize(2);
    assertThat(answer.status).isEqualTo(400);
    assertThat(answer.credentialFailure).isFalse();
  }

  @Test
  public void cooldown_and_cap_come_from_the_authenticator_config() {
    var config = new AuthenticatorConfigModel();
    config.setAlias("email-otp-config");
    config.setConfig(Map.of("length", "6", "ttl", "900",
        "resendCooldownSeconds", "60", "maxMailsPerWindow", "2", "mailWindowSeconds", "600"));
    authenticator = new OtpMailAuthenticator(fx.otpService, fx.credentialService, fx.mailSender,
        fx.throttleFromConfig(config));

    assertThat(tokenRequest(null).challenge.getResendAvailableInSeconds()).isEqualTo(60);
    fx.clock.advanceSeconds(45);
    assertThat(tokenRequest(null).challenge.getResendAvailableInSeconds()).isEqualTo(15);
    fx.clock.advanceSeconds(15);
    var second = tokenRequest(null);
    assertThat(fx.mailedCodes).hasSize(2);
    assertThat(second.challenge.getResendAvailableInSeconds()).isEqualTo(600 - 60);
    fx.clock.advanceSeconds(60);
    var third = tokenRequest(null);

    assertThat(third.status).isEqualTo(429);
    assertThat(fx.mailedCodes).hasSize(2);
  }

  @Test
  public void a_credential_stored_before_this_change_keeps_working() {
    // credential data as the previous image wrote it: no send history
    fx.overwriteStoredCredentialData(
        "{\"ttlInSeconds\":900,\"email\":\"counsellor@example.org\","
            + "\"failedVerifications\":0,\"active\":true}");

    var answer = tokenRequest(null);

    assertThat(answer.status).isEqualTo(400);
    assertThat(answer.credentialFailure).isFalse();
    assertThat(fx.mailedCodes).hasSize(1);
    assertThat(tokenRequest(fx.lastMailedCode()).succeeded).isTrue();
  }

  @Test
  public void credential_data_with_fields_from_a_newer_image_can_still_be_read() {
    // A later image may add fields again; reading must not break the login on a rollback.
    fx.overwriteStoredCredentialData(
        "{\"ttlInSeconds\":900,\"email\":\"counsellor@example.org\","
            + "\"failedVerifications\":0,\"active\":true,\"somethingNew\":42}");

    assertThat(tokenRequest(null).status).isEqualTo(400);
  }

  private TokenAnswer tokenRequest(String otp) {
    var flow = mock(AuthenticationFlowContext.class);
    var httpRequest = mock(HttpRequest.class);
    var params = new MultivaluedHashMap<String, String>();
    if (otp != null) {
      params.putSingle("otp", otp);
    }
    when(flow.getHttpRequest()).thenReturn(httpRequest);
    when(httpRequest.getDecodedFormParameters()).thenReturn(params);
    when(flow.getSession()).thenReturn(fx.session);
    when(flow.getRealm()).thenReturn(fx.realm);
    when(flow.getUser()).thenReturn(fx.user);

    var answer = new TokenAnswer();
    doAnswer(invocation -> {
      answer.credentialFailure = true;
      recordResponse(answer, invocation.getArgument(1));
      return null;
    }).when(flow).failure(any(), any(Response.class));
    doAnswer(invocation -> {
      recordResponse(answer, invocation.getArgument(0));
      return null;
    }).when(flow).challenge(any(Response.class));
    doAnswer(invocation -> {
      answer.succeeded = true;
      return null;
    }).when(flow).success();

    authenticator.authenticate(flow);
    return answer;
  }

  private void recordResponse(TokenAnswer answer, Response response) {
    answer.status = response.getStatus();
    answer.retryAfter = response.getHeaderString("Retry-After");
    if (response.getEntity() instanceof Challenge) {
      answer.challenge = (Challenge) response.getEntity();
    }
  }

  private static final class TokenAnswer {

    int status;
    String retryAfter;
    Challenge challenge;
    boolean succeeded;
    boolean credentialFailure;
  }
}
