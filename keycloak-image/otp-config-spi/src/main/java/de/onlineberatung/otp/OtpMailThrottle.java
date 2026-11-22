package de.onlineberatung.otp;

import static java.util.Objects.isNull;

import java.time.Clock;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import javax.annotation.Nullable;
import org.jboss.logging.Logger;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * Decides whether another e-mail code may be mailed now (#1338).
 *
 * <p>Two brakes: a cooldown after each mail, during which the last code stays valid and nothing is
 * sent, and a cap of mails per sliding window. The send history it works on is stored in the
 * credential, so every Keycloak pod sees the same history and a restart forgets nothing.
 */
public class OtpMailThrottle {

  public static final String COOLDOWN_SECONDS_KEY = "resendCooldownSeconds";
  public static final String MAX_MAILS_KEY = "maxMailsPerWindow";
  public static final String WINDOW_SECONDS_KEY = "mailWindowSeconds";

  static final int DEFAULT_COOLDOWN_SECONDS = 30;
  static final int DEFAULT_MAX_MAILS = 5;
  static final int DEFAULT_WINDOW_SECONDS = 900;

  private static final Logger logger = Logger.getLogger(OtpMailThrottle.class);
  private static final long SECOND_IN_MILLIS = 1000L;

  private final Clock clock;
  private final long cooldownMillis;
  private final int maxMails;
  private final long windowMillis;

  public OtpMailThrottle(Clock clock, int cooldownSeconds, int maxMails, int windowSeconds) {
    this.clock = clock;
    this.cooldownMillis = cooldownSeconds * SECOND_IN_MILLIS;
    this.maxMails = maxMails;
    this.windowMillis = windowSeconds * SECOND_IN_MILLIS;
  }

  /** Reads the brakes from the realm's {@code email-otp-config}; a missing key means default. */
  public static OtpMailThrottle fromConfig(Clock clock, @Nullable AuthenticatorConfigModel config) {
    var values = isNull(config) || isNull(config.getConfig())
        ? Collections.<String, String>emptyMap() : config.getConfig();
    return new OtpMailThrottle(clock,
        readSeconds(values.get(COOLDOWN_SECONDS_KEY), DEFAULT_COOLDOWN_SECONDS, 0),
        readSeconds(values.get(MAX_MAILS_KEY), DEFAULT_MAX_MAILS, 1),
        readSeconds(values.get(WINDOW_SECONDS_KEY), DEFAULT_WINDOW_SECONDS, 1));
  }

  public Clock clock() {
    return clock;
  }

  /** The three settings as they appear in the admin console, shared by both authenticators. */
  public static List<ProviderConfigProperty> configProperties() {
    return List.of(
        new ProviderConfigProperty(COOLDOWN_SECONDS_KEY, "Resend cooldown (seconds)",
            "After a code was mailed, no new code is mailed for this many seconds; the last "
                + "code stays valid.", ProviderConfigProperty.STRING_TYPE,
            String.valueOf(DEFAULT_COOLDOWN_SECONDS)),
        new ProviderConfigProperty(MAX_MAILS_KEY, "Maximum code mails per window",
            "At most this many code mails per user within the window; further requests are "
                + "refused with HTTP 429.", ProviderConfigProperty.STRING_TYPE,
            String.valueOf(DEFAULT_MAX_MAILS)),
        new ProviderConfigProperty(WINDOW_SECONDS_KEY, "Mail window (seconds)",
            "Length of the sliding window for the maximum number of code mails.",
            ProviderConfigProperty.STRING_TYPE, String.valueOf(DEFAULT_WINDOW_SECONDS)));
  }

  /**
   * @param mailsSentAt when the last mails went out (epoch millis), as stored in the credential
   * @param liveCodeExists whether the stored code can still be typed in; a code that was used or
   *     expired has nothing the cooldown could protect
   */
  public Decision decide(@Nullable List<Long> mailsSentAt, boolean liveCodeExists) {
    var now = clock.millis();
    var recent = withinWindow(mailsSentAt, now);

    if (recent.size() >= maxMails) {
      return new Decision(Verdict.LIMIT_REACHED, secondsUntil(capEndsAt(recent), now));
    }
    if (liveCodeExists && !recent.isEmpty()) {
      var cooldownEndsAt = last(recent) + cooldownMillis;
      if (cooldownEndsAt > now) {
        return new Decision(Verdict.WAIT, secondsUntil(cooldownEndsAt, now));
      }
    }
    return new Decision(Verdict.SEND, 0);
  }

  /** The history to store once a mail goes out now: only what the window still needs. */
  public List<Long> recordMail(@Nullable List<Long> mailsSentAt) {
    var now = clock.millis();
    var updated = withinWindow(mailsSentAt, now);
    updated.add(now);
    while (updated.size() > maxMails) {
      updated.remove(0);
    }
    return updated;
  }

  /** Seconds until the next mail may go out, given the history right after a mail was sent. */
  public long secondsUntilNextMail(List<Long> mailsSentAtAfterSend) {
    var now = clock.millis();
    var recent = withinWindow(mailsSentAtAfterSend, now);
    var nextAt = recent.isEmpty() ? now : last(recent) + cooldownMillis;
    if (recent.size() >= maxMails) {
      nextAt = Math.max(nextAt, capEndsAt(recent));
    }
    return secondsUntil(nextAt, now);
  }

  private List<Long> withinWindow(@Nullable List<Long> mailsSentAt, long now) {
    if (isNull(mailsSentAt)) {
      return new ArrayList<>();
    }
    return mailsSentAt.stream()
        // a timestamp slightly ahead of this pod's clock (another pod wrote it) is kept:
        // dropping it would let clock skew open the cooldown
        .filter(sentAt -> sentAt != null && sentAt > now - windowMillis)
        .sorted()
        .collect(Collectors.toCollection(ArrayList::new));
  }

  private long capEndsAt(List<Long> recent) {
    // the mail that has to leave the window before one more fits under the cap
    return recent.get(recent.size() - maxMails) + windowMillis;
  }

  private static long last(List<Long> sorted) {
    return sorted.get(sorted.size() - 1);
  }

  private static long secondsUntil(long at, long now) {
    // rounded up, so a client that waits exactly this long is never refused
    return Math.max(0, (at - now + SECOND_IN_MILLIS - 1) / SECOND_IN_MILLIS);
  }

  private static int readSeconds(@Nullable String raw, int fallback, int minimum) {
    if (isNull(raw) || raw.isBlank()) {
      return fallback;
    }
    try {
      var parsed = Integer.parseInt(raw.trim());
      if (parsed >= minimum) {
        return parsed;
      }
    } catch (NumberFormatException e) {
      // fall through to the warning
    }
    logger.warn("invalid e-mail OTP throttle setting '" + raw + "', using " + fallback);
    return fallback;
  }

  public enum Verdict {
    /** Mail a new code. */
    SEND,
    /** Inside the cooldown: send nothing, the last code stays valid. */
    WAIT,
    /** The cap for the window is used up: send nothing, answer 429. */
    LIMIT_REACHED
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

    public long getRetryInSeconds() {
      return retryInSeconds;
    }
  }
}
