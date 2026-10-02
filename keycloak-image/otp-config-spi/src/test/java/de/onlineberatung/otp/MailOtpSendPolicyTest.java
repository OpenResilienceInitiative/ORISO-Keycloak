package de.onlineberatung.otp;

import static org.assertj.core.api.Assertions.assertThat;

import de.onlineberatung.credential.MailOtpCredentialModel;
import de.onlineberatung.otp.MailOtpSendPolicy.Verdict;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Map;
import org.junit.Test;
import org.keycloak.models.AuthenticatorConfigModel;

/** The cooldown and the per-window ceiling on code mails (ORISO-UserService#1338). */
public class MailOtpSendPolicyTest {

  /** A clock the test moves on purpose; wall-clock time must never decide an assertion. */
  private static final class MovableClock extends Clock {

    private Instant now = Instant.parse("2026-10-02T10:00:00Z");

    @Override
    public ZoneOffset getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(java.time.ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return now;
    }

    void advanceSeconds(long seconds) {
      now = now.plusSeconds(seconds);
    }

    void rewindSeconds(long seconds) {
      now = now.minusSeconds(seconds);
    }
  }

  private final MovableClock clock = new MovableClock();

  private MailOtpCredentialModel credential() {
    var otp = new Otp("123456", 900, clock.millis() + 900_000, "berater@example.org", 0);
    return MailOtpCredentialModel.createOtpModel(otp, clock, true);
  }

  private MailOtpSendPolicy policy() {
    return new MailOtpSendPolicy(clock, 30, 5, 900);
  }

  @Test
  public void decide_allows_the_first_mail_for_a_credential_that_never_sent_one() {
    // every credential written before #1338 reports 0 for the new fields; it must not be stuck
    var decision = policy().decide(credential());

    assertThat(decision.verdict()).isEqualTo(Verdict.SEND);
    assertThat(decision.retryAfterSeconds()).isEqualTo(30);
  }

  @Test
  public void decide_refuses_a_second_mail_inside_the_cooldown_and_reports_the_wait() {
    var policy = policy();
    var credential = credential();
    policy.recordSent(credential);

    clock.advanceSeconds(10);
    var decision = policy.decide(credential);

    assertThat(decision.verdict()).isEqualTo(Verdict.COOLDOWN);
    assertThat(decision.retryAfterSeconds()).isEqualTo(20);
    assertThat(decision.maySend()).isFalse();
  }

  @Test
  public void decide_allows_the_next_mail_once_the_cooldown_has_passed() {
    var policy = policy();
    var credential = credential();
    policy.recordSent(credential);

    clock.advanceSeconds(30);

    assertThat(policy.decide(credential).verdict()).isEqualTo(Verdict.SEND);
  }

  @Test
  public void decide_caps_the_sixth_mail_in_the_window_and_reports_when_the_window_ends() {
    var policy = policy();
    var credential = credential();
    for (var i = 0; i < 5; i++) {
      assertThat(policy.decide(credential).verdict()).isEqualTo(Verdict.SEND);
      policy.recordSent(credential);
      clock.advanceSeconds(31);
    }

    var decision = policy.decide(credential);

    assertThat(decision.verdict()).isEqualTo(Verdict.CAPPED);
    // the window started at the first of the five sends, 5 * 31 s ago
    assertThat(decision.retryAfterSeconds()).isEqualTo(900 - 155);
  }

  @Test
  public void decide_allows_sending_again_once_the_window_has_rolled() {
    var policy = policy();
    var credential = credential();
    for (var i = 0; i < 5; i++) {
      policy.recordSent(credential);
      clock.advanceSeconds(31);
    }
    assertThat(policy.decide(credential).verdict()).isEqualTo(Verdict.CAPPED);

    clock.advanceSeconds(900);

    assertThat(policy.decide(credential).verdict()).isEqualTo(Verdict.SEND);
  }

  @Test
  public void recordSent_starts_a_fresh_window_when_the_old_one_has_expired() {
    var policy = policy();
    var credential = credential();
    policy.recordSent(credential);
    assertThat(credential.getMailsSentInWindow()).isEqualTo(1);

    clock.advanceSeconds(901);
    policy.recordSent(credential);

    assertThat(credential.getMailsSentInWindow()).isEqualTo(1);
    assertThat(credential.getSendWindowStartedAt()).isEqualTo(clock.millis());
  }

  @Test
  public void recordSent_counts_within_an_open_window() {
    var policy = policy();
    var credential = credential();
    policy.recordSent(credential);
    var windowStart = credential.getSendWindowStartedAt();

    clock.advanceSeconds(31);
    policy.recordSent(credential);

    assertThat(credential.getMailsSentInWindow()).isEqualTo(2);
    assertThat(credential.getSendWindowStartedAt()).isEqualTo(windowStart);
  }

  @Test
  public void decide_caps_the_wait_at_the_cooldown_when_the_timestamp_lies_in_the_future() {
    // A clock correction, or a replica running ahead, leaves a send stamped later than "now". The
    // wait must stay bounded by the cooldown instead of growing to the size of the skew: one hour
    // of drift must not mean one hour without a login.
    var policy = policy();
    var credential = credential();
    policy.recordSent(credential);
    clock.rewindSeconds(3600);

    var decision = policy.decide(credential);

    assertThat(decision.retryAfterSeconds()).isLessThanOrEqualTo(30);
  }

  @Test
  public void decide_leaves_the_credential_untouched_when_it_refuses() {
    var policy = policy();
    var credential = credential();
    policy.recordSent(credential);
    var code = credential.getOtp().getCode();
    var sent = credential.getMailsSentInWindow();

    clock.advanceSeconds(5);
    policy.decide(credential);

    // the code in the user's inbox is the one they are about to type
    assertThat(credential.getOtp().getCode()).isEqualTo(code);
    assertThat(credential.getMailsSentInWindow()).isEqualTo(sent);
  }

  @Test
  public void thresholds_come_from_the_authenticator_config() {
    var policy = new MailOtpSendPolicy(clock, configWith(Map.of(
        MailOtpSendPolicy.COOLDOWN_CONFIG_KEY, "60",
        MailOtpSendPolicy.MAX_SENDS_CONFIG_KEY, "2",
        MailOtpSendPolicy.WINDOW_CONFIG_KEY, "600")));
    var credential = credential();

    assertThat(policy.cooldownSeconds()).isEqualTo(60);
    policy.recordSent(credential);
    clock.advanceSeconds(61);
    policy.recordSent(credential);
    clock.advanceSeconds(61);

    assertThat(policy.decide(credential).verdict()).isEqualTo(Verdict.CAPPED);
  }

  @Test
  public void unusable_config_values_fall_back_to_the_defaults_instead_of_disabling_the_brake() {
    var policy = new MailOtpSendPolicy(clock, configWith(Map.of(
        MailOtpSendPolicy.COOLDOWN_CONFIG_KEY, "not a number",
        MailOtpSendPolicy.MAX_SENDS_CONFIG_KEY, "0",
        MailOtpSendPolicy.WINDOW_CONFIG_KEY, "-5")));

    assertThat(policy.cooldownSeconds()).isEqualTo(MailOtpSendPolicy.DEFAULT_COOLDOWN_SECONDS);

    var credential = credential();
    for (var i = 0; i < MailOtpSendPolicy.DEFAULT_MAX_SENDS_PER_WINDOW; i++) {
      policy.recordSent(credential);
      clock.advanceSeconds(MailOtpSendPolicy.DEFAULT_COOLDOWN_SECONDS + 1L);
    }

    assertThat(policy.decide(credential).verdict()).isEqualTo(Verdict.CAPPED);
  }

  @Test
  public void a_missing_authenticator_config_uses_the_defaults() {
    var policy = new MailOtpSendPolicy(clock, null);

    assertThat(policy.cooldownSeconds()).isEqualTo(MailOtpSendPolicy.DEFAULT_COOLDOWN_SECONDS);
    assertThat(policy.decide(credential()).verdict()).isEqualTo(Verdict.SEND);
  }

  private AuthenticatorConfigModel configWith(Map<String, String> values) {
    var config = new AuthenticatorConfigModel();
    config.setAlias("email-otp-config");
    config.setConfig(new HashMap<>(values));
    return config;
  }
}
