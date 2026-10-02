package de.onlineberatung.otp;

import static java.util.Objects.nonNull;

import de.onlineberatung.credential.MailOtpCredentialModel;
import java.time.Clock;
import javax.annotation.Nullable;
import org.jboss.logging.Logger;
import org.keycloak.models.AuthenticatorConfigModel;

/**
 * The brake on e-mail one-time codes (ORISO-UserService#1338).
 *
 * <p>Before this policy existed, every request without a code produced a fresh mail: no wait, no
 * ceiling, and the failed-attempt counter started again with each one. Anyone who knew a password
 * could mail-bomb the account owner and buy three new guesses per mail, without limit.
 *
 * <p>Two limits, both read from the authenticator config so they can be changed without a release:
 *
 * <ul>
 *   <li><b>cooldown</b> — within {@value #DEFAULT_COOLDOWN_SECONDS} seconds of the last mail, no
 *       new mail is sent and the code already in the user's inbox stays valid. This is the one that
 *       makes the "send new code" link safe to click twice.
 *   <li><b>cap</b> — at most {@value #DEFAULT_MAX_SENDS_PER_WINDOW} mails per rolling window of
 *       {@value #DEFAULT_WINDOW_SECONDS} seconds per user. This is the one that bounds guessing: a
 *       code allows three attempts, so the budget is 15 guesses per quarter hour instead of
 *       unlimited.
 * </ul>
 *
 * <p>The bookkeeping lives in the stored credential, not in memory: the limits must hold across
 * replicas and restarts, and an attacker must not be able to reset them by hitting another pod.
 *
 * <p>Deliberately NOT done here: making the per-code failure counter survive a new code. Three
 * mistyped digits would then lock the person out until the window rolled, and for an advice-seeking
 * audience that is the worse failure. The cap above is what bounds the attacker; see the note in
 * the pull request for #1338.
 */
public class MailOtpSendPolicy {

  public static final int DEFAULT_COOLDOWN_SECONDS = 30;
  public static final int DEFAULT_MAX_SENDS_PER_WINDOW = 5;
  public static final int DEFAULT_WINDOW_SECONDS = 900;

  public static final String COOLDOWN_CONFIG_KEY = "resendCooldownSeconds";
  public static final String MAX_SENDS_CONFIG_KEY = "maxSendsPerWindow";
  public static final String WINDOW_CONFIG_KEY = "sendWindowSeconds";

  private static final Logger logger = Logger.getLogger(MailOtpSendPolicy.class);
  private static final long SECOND_IN_MILLIS = 1000L;

  /** What to do with a request that carries no code. */
  public enum Verdict {
    /** Create a new code, send it, and record the send. */
    SEND,
    /** Too soon. Keep the current code, send nothing, tell the client how long to wait. */
    COOLDOWN,
    /** The per-window ceiling is reached. Send nothing and answer 429. */
    CAPPED
  }

  /** The verdict plus the number of seconds the client should wait before asking again. */
  public static final class Decision {

    private final Verdict verdict;
    private final int retryAfterSeconds;

    private Decision(Verdict verdict, int retryAfterSeconds) {
      this.verdict = verdict;
      this.retryAfterSeconds = Math.max(retryAfterSeconds, 0);
    }

    public Verdict verdict() {
      return verdict;
    }

    /** Seconds until the next mail is allowed; for {@code SEND} this is the cooldown ahead. */
    public int retryAfterSeconds() {
      return retryAfterSeconds;
    }

    public boolean maySend() {
      return verdict == Verdict.SEND;
    }
  }

  private final Clock clock;
  private final int cooldownSeconds;
  private final int maxSendsPerWindow;
  private final int windowSeconds;

  public MailOtpSendPolicy(Clock clock, @Nullable AuthenticatorConfigModel authConfig) {
    this.clock = clock;
    this.cooldownSeconds =
        positiveConfig(authConfig, COOLDOWN_CONFIG_KEY, DEFAULT_COOLDOWN_SECONDS);
    this.maxSendsPerWindow =
        positiveConfig(authConfig, MAX_SENDS_CONFIG_KEY, DEFAULT_MAX_SENDS_PER_WINDOW);
    this.windowSeconds = positiveConfig(authConfig, WINDOW_CONFIG_KEY, DEFAULT_WINDOW_SECONDS);
  }

  MailOtpSendPolicy(Clock clock, int cooldownSeconds, int maxSendsPerWindow, int windowSeconds) {
    this.clock = clock;
    this.cooldownSeconds = cooldownSeconds;
    this.maxSendsPerWindow = maxSendsPerWindow;
    this.windowSeconds = windowSeconds;
  }

  public int cooldownSeconds() {
    return cooldownSeconds;
  }

  /** Whether this request may produce a mail, and how long the client should wait if not. */
  public Decision decide(MailOtpCredentialModel credentialModel) {
    var now = clock.millis();
    var lastSentAt = notInTheFuture(credentialModel.getLastMailSentAt(), now);

    // A never-sent credential (every row written before this change) reports 0 and is allowed
    // through once. The record it writes then puts it under both limits.
    if (lastSentAt > 0) {
      var cooldownEndsAt = lastSentAt + cooldownSeconds * SECOND_IN_MILLIS;
      if (now < cooldownEndsAt) {
        return new Decision(Verdict.COOLDOWN, secondsUntil(cooldownEndsAt, now));
      }
    }

    var windowStartedAt = notInTheFuture(credentialModel.getSendWindowStartedAt(), now);
    var windowEndsAt = windowStartedAt + windowSeconds * SECOND_IN_MILLIS;
    var windowIsOpen = windowStartedAt > 0 && now < windowEndsAt;
    if (windowIsOpen && credentialModel.getMailsSentInWindow() >= maxSendsPerWindow) {
      return new Decision(Verdict.CAPPED, secondsUntil(windowEndsAt, now));
    }

    return new Decision(Verdict.SEND, cooldownSeconds);
  }

  /**
   * Writes the send into the credential. Call this on the model that is about to be stored, so the
   * code and its bookkeeping are persisted in one update — a mail counted but not stored is a limit
   * that quietly does not apply.
   */
  public void recordSent(MailOtpCredentialModel credentialModel) {
    var now = clock.millis();
    var windowStartedAt = notInTheFuture(credentialModel.getSendWindowStartedAt(), now);
    var windowHasRolled = windowStartedAt == 0 || now >= windowStartedAt + windowMillis();

    var startOfWindow = windowHasRolled ? now : windowStartedAt;
    var sentInWindow = windowHasRolled ? 1 : credentialModel.getMailsSentInWindow() + 1;

    credentialModel.applySendBookkeeping(now, startOfWindow, sentInWindow);
  }

  private long windowMillis() {
    return windowSeconds * SECOND_IN_MILLIS;
  }

  /**
   * A timestamp ahead of the current clock would park a user behind the cooldown for as long as the
   * skew lasts. Clock changes and replicas drifting apart are real; a stuck login is not an
   * acceptable answer to either, so the future is read as "now".
   */
  private long notInTheFuture(long timestamp, long now) {
    return timestamp > now ? now : timestamp;
  }

  private int secondsUntil(long deadline, long now) {
    return (int) Math.max(1, (deadline - now + SECOND_IN_MILLIS - 1) / SECOND_IN_MILLIS);
  }

  private int positiveConfig(
      @Nullable AuthenticatorConfigModel authConfig, String key, int fallback) {
    if (nonNull(authConfig) && nonNull(authConfig.getConfig())) {
      var raw = authConfig.getConfig().get(key);
      if (nonNull(raw) && !raw.isBlank()) {
        try {
          var parsed = Integer.parseInt(raw.trim());
          if (parsed > 0) {
            return parsed;
          }
          logger.warn("otp send policy: " + key + " must be positive, was " + parsed
              + ". Using default " + fallback);
        } catch (NumberFormatException e) {
          logger.warn("otp send policy: " + key + " is not a number (" + raw + "). Using default "
              + fallback);
        }
      }
    }
    return fallback;
  }
}
