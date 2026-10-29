package de.onlineberatung.otp;

import static java.util.Objects.isNull;

import java.time.Clock;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.annotation.Nullable;
import org.jboss.logging.Logger;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * Locks the e-mail second factor for a while once the attempt limit is reached, and for longer
 * every time it happens again (#1338).
 *
 * <p>Without this, the attempt limit costs an attacker nothing: three wrong codes kill the code,
 * and asking for a new one starts three fresh attempts straight away. The only brake left is the
 * mail cap, which runs out after fifteen minutes and then allows the next five guesses. The limit
 * looks like a lockout and is a speed bump.
 *
 * <p>So the limit now starts a lockout, and the lockout grows: a minute, then 24 minutes, then an
 * hour, and so on up to a day, which is the ceiling. Nothing the locked-out person can do shortens
 * it — asking for a new code is refused with the same wait, because a resend that cleared the
 * lockout would be the hole this closes. A successful login clears the ladder, and so does a day
 * of quiet, so a person who mistypes twice in a month never meets the long steps.
 *
 * <p>The state lives in the credential, like the mail history: every pod sees the same lockout and
 * a restart forgets nothing.
 */
public class OtpFailureLockout {

  public static final String LADDER_KEY = "failureLockoutLadderSeconds";
  public static final String RESET_SECONDS_KEY = "failureLockoutResetSeconds";

  /** A minute, 24 minutes, an hour, six hours, a day — the last step is the ceiling. */
  static final String DEFAULT_LADDER = "60,1440,3600,21600,86400";
  static final int DEFAULT_RESET_SECONDS = 86400;

  private static final Logger logger = Logger.getLogger(OtpFailureLockout.class);
  private static final long SECOND_IN_MILLIS = 1000L;

  private final Clock clock;
  private final List<Long> ladderSeconds;
  private final long resetMillis;

  public OtpFailureLockout(Clock clock, List<Long> ladderSeconds, int resetSeconds) {
    this.clock = clock;
    this.ladderSeconds = List.copyOf(ladderSeconds);
    this.resetMillis = resetSeconds * SECOND_IN_MILLIS;
  }

  /** Reads the ladder from the realm's {@code email-otp-config}; a missing key means default. */
  public static OtpFailureLockout fromConfig(Clock clock,
      @Nullable AuthenticatorConfigModel config) {
    var values = isNull(config) || isNull(config.getConfig())
        ? Collections.<String, String>emptyMap() : config.getConfig();
    return new OtpFailureLockout(clock, readLadder(values.get(LADDER_KEY)),
        readSeconds(values.get(RESET_SECONDS_KEY), DEFAULT_RESET_SECONDS));
  }

  /** The two settings as they appear in the admin console, shared by both authenticators. */
  public static List<ProviderConfigProperty> configProperties() {
    return List.of(
        new ProviderConfigProperty(LADDER_KEY, "Failed-attempt lockout ladder (seconds)",
            "Comma-separated waits, one per time the attempt limit is reached again. The last "
                + "value is the ceiling and repeats.", ProviderConfigProperty.STRING_TYPE,
            DEFAULT_LADDER),
        new ProviderConfigProperty(RESET_SECONDS_KEY, "Lockout ladder reset (seconds)",
            "After this much quiet since the last lockout ended, the ladder starts at its first "
                + "step again.", ProviderConfigProperty.STRING_TYPE,
            String.valueOf(DEFAULT_RESET_SECONDS)));
  }

  public Clock clock() {
    return clock;
  }

  /**
   * Whether the second factor is locked right now.
   *
   * @param lockedUntil epoch millis from the credential, null for a credential never locked
   */
  public Decision decide(@Nullable Long lockedUntil) {
    var now = clock.millis();
    if (isNull(lockedUntil) || lockedUntil <= now) {
      return new Decision(Verdict.OPEN, 0);
    }
    return new Decision(Verdict.LOCKED, secondsUntil(lockedUntil, now));
  }

  /**
   * The lockout that follows the attempt limit being reached now.
   *
   * @param lockedUntil when the previous lockout ended, null when there was none
   * @param previousLevel how many lockouts the previous one was, 0 when there was none
   */
  public Lock escalate(@Nullable Long lockedUntil, int previousLevel) {
    var now = clock.millis();
    var quietSinceLastLockout =
        isNull(lockedUntil) || lockedUntil <= now - resetMillis;
    var level = quietSinceLastLockout || previousLevel < 1
        ? 1
        : Math.min(previousLevel + 1, ladderSeconds.size());
    var waitSeconds = ladderSeconds.get(level - 1);
    return new Lock(now + waitSeconds * SECOND_IN_MILLIS, level, waitSeconds);
  }

  private static List<Long> readLadder(@Nullable String raw) {
    if (isNull(raw) || raw.isBlank()) {
      return parseLadder(DEFAULT_LADDER);
    }
    var parsed = parseLadder(raw);
    if (parsed.isEmpty()) {
      logger.warn("invalid e-mail OTP lockout ladder '" + raw + "', using " + DEFAULT_LADDER);
      return parseLadder(DEFAULT_LADDER);
    }
    return parsed;
  }

  private static List<Long> parseLadder(String raw) {
    var steps = new ArrayList<Long>();
    for (var part : raw.split(",")) {
      try {
        var seconds = Long.parseLong(part.trim());
        if (seconds > 0) {
          steps.add(seconds);
        }
      } catch (NumberFormatException e) {
        // a single unreadable step must not throw away the readable ones
        logger.warn("ignoring unreadable e-mail OTP lockout step '" + part + "'");
      }
    }
    return steps;
  }

  private static int readSeconds(@Nullable String raw, int fallback) {
    if (isNull(raw) || raw.isBlank()) {
      return fallback;
    }
    try {
      var parsed = Integer.parseInt(raw.trim());
      if (parsed >= 0) {
        return parsed;
      }
    } catch (NumberFormatException e) {
      // fall through to the warning
    }
    logger.warn("invalid e-mail OTP lockout reset '" + raw + "', using " + fallback);
    return fallback;
  }

  private static long secondsUntil(long at, long now) {
    // rounded up, so a client that waits exactly this long is never refused
    return Math.max(0, (at - now + SECOND_IN_MILLIS - 1) / SECOND_IN_MILLIS);
  }

  public enum Verdict {
    /** No lockout is running: check the code as usual. */
    OPEN,
    /** Locked: check nothing, mail nothing, and say for how long. */
    LOCKED
  }

  public static final class Decision {

    private final Verdict verdict;
    private final long retryInSeconds;

    Decision(Verdict verdict, long retryInSeconds) {
      this.verdict = verdict;
      this.retryInSeconds = retryInSeconds;
    }

    public Verdict getVerdict() {
      return verdict;
    }

    public boolean isLocked() {
      return verdict == Verdict.LOCKED;
    }

    /** Seconds until the second factor accepts a code again. */
    public long getRetryInSeconds() {
      return retryInSeconds;
    }
  }

  /** A lockout to store: when it ends, which step of the ladder it is, and how long it lasts. */
  public static final class Lock {

    private final long lockedUntil;
    private final int level;
    private final long waitSeconds;

    Lock(long lockedUntil, int level, long waitSeconds) {
      this.lockedUntil = lockedUntil;
      this.level = level;
      this.waitSeconds = waitSeconds;
    }

    public long getLockedUntil() {
      return lockedUntil;
    }

    public int getLevel() {
      return level;
    }

    public long getWaitSeconds() {
      return waitSeconds;
    }
  }
}
