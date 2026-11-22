package de.onlineberatung.otp;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.List;
import java.util.Map;
import org.junit.Test;
import org.keycloak.models.AuthenticatorConfigModel;

/**
 * The escalating lockout the attempt limit starts (#1338).
 *
 * <p>The ladder is the whole protection: without it, three wrong codes cost one mail and the
 * guessing continues. These tests pin how long each step is, that the last step is a ceiling and
 * not a dead end, and that a quiet person never reaches the long steps.
 */
public class OtpFailureLockoutTest {

  private final MutableClock clock = new MutableClock(Instant.parse("2026-10-19T10:00:00Z"));

  private OtpFailureLockout lockout() {
    return OtpFailureLockout.fromConfig(clock, null);
  }

  @Test
  public void a_credential_that_was_never_locked_is_open() {
    var decision = lockout().decide(null);

    assertThat(decision.isLocked()).isFalse();
    assertThat(decision.getRetryInSeconds()).isZero();
  }

  @Test
  public void the_default_ladder_is_a_minute_then_24_minutes_then_an_hour_up_to_a_day() {
    var subject = lockout();
    var steps = new java.util.ArrayList<Long>();
    Long lockedUntil = null;
    var level = 0;

    for (var i = 0; i < 7; i++) {
      var lock = subject.escalate(lockedUntil, level);
      steps.add(lock.getWaitSeconds());
      lockedUntil = lock.getLockedUntil();
      level = lock.getLevel();
      // straight back to guessing the moment the lockout ends
      clock.advance(Duration.ofSeconds(lock.getWaitSeconds()));
    }

    assertThat(steps).containsExactly(60L, 1440L, 3600L, 21600L, 86400L, 86400L, 86400L);
  }

  @Test
  public void the_remaining_wait_is_rounded_up_so_a_client_never_comes_back_early() {
    var lock = lockout().escalate(null, 0);

    clock.advance(Duration.ofMillis(59_001));
    var decision = lockout().decide(lock.getLockedUntil());

    assertThat(decision.isLocked()).isTrue();
    assertThat(decision.getRetryInSeconds()).isEqualTo(1);
  }

  @Test
  public void the_lockout_is_over_the_moment_it_expires() {
    var lock = lockout().escalate(null, 0);

    clock.advance(Duration.ofSeconds(60));

    assertThat(lockout().decide(lock.getLockedUntil()).isLocked()).isFalse();
  }

  @Test
  public void a_day_of_quiet_puts_the_ladder_back_on_its_first_step() {
    var first = lockout().escalate(null, 0);
    clock.advance(Duration.ofSeconds(60));

    clock.advance(Duration.ofDays(1));
    var next = lockout().escalate(first.getLockedUntil(), first.getLevel());

    // Someone who mistypes three times twice in a month is not under attack.
    assertThat(next.getWaitSeconds()).isEqualTo(60);
    assertThat(next.getLevel()).isEqualTo(1);
  }

  @Test
  public void the_ladder_and_the_reset_come_from_the_authenticator_config() {
    var config = new AuthenticatorConfigModel();
    config.setConfig(Map.of("failureLockoutLadderSeconds", " 30, 90 ",
        "failureLockoutResetSeconds", "120"));
    var subject = OtpFailureLockout.fromConfig(clock, config);

    var first = subject.escalate(null, 0);
    assertThat(first.getWaitSeconds()).isEqualTo(30);

    clock.advance(Duration.ofSeconds(30));
    var second = subject.escalate(first.getLockedUntil(), first.getLevel());
    assertThat(second.getWaitSeconds()).isEqualTo(90);
  }

  @Test
  public void an_unreadable_ladder_falls_back_to_the_default_rather_than_to_no_lockout() {
    var config = new AuthenticatorConfigModel();
    config.setConfig(Map.of("failureLockoutLadderSeconds", "soon, later"));

    var lock = OtpFailureLockout.fromConfig(clock, config).escalate(null, 0);

    assertThat(lock.getWaitSeconds()).isEqualTo(60);
  }

  @Test
  public void an_unreadable_step_is_dropped_and_the_readable_ones_are_kept() {
    var config = new AuthenticatorConfigModel();
    config.setConfig(Map.of("failureLockoutLadderSeconds", "45,soon,0,-9,900"));
    var subject = OtpFailureLockout.fromConfig(clock, config);

    var first = subject.escalate(null, 0);
    clock.advance(Duration.ofSeconds(45));
    var second = subject.escalate(first.getLockedUntil(), first.getLevel());

    assertThat(List.of(first.getWaitSeconds(), second.getWaitSeconds()))
        .containsExactly(45L, 900L);
  }

  private static final class MutableClock extends Clock {

    private Instant now;

    MutableClock(Instant start) {
      this.now = start;
    }

    void advance(Duration duration) {
      now = now.plus(duration);
    }

    @Override
    public ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return now;
    }
  }
}
