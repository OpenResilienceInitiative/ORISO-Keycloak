package de.onlineberatung.authenticator;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import de.onlineberatung.credential.CredentialContext;
import de.onlineberatung.credential.MailOtpCredentialModel;
import de.onlineberatung.credential.MailOtpCredentialProvider;
import de.onlineberatung.credential.MailOtpCredentialService;
import de.onlineberatung.mail.MailSendingException;
import de.onlineberatung.otp.MemoryOtpService;
import de.onlineberatung.otp.Otp;
import de.onlineberatung.otp.OtpMailSender;
import de.onlineberatung.otp.OtpMailThrottle;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * A user with an active e-mail second factor, a clock the test moves by hand, and a credential
 * store that only keeps the serialized strings.
 *
 * <p>Every read deserializes what the last write stored, exactly like a second Keycloak pod
 * reading the database would. Anything the cooldown or the cap needs that is not in the stored
 * credential is lost between two requests here, as it would be between two pods.
 */
class MailOtpLoginFixture {

  static final String EMAIL = "counsellor@example.org";

  final MutableClock clock = new MutableClock(Instant.parse("2026-10-02T10:00:00Z"));
  final List<Otp> mailedCodes = new ArrayList<>();
  final OtpMailSender mailSender;
  final MailOtpCredentialService credentialService;
  final MemoryOtpService otpService;
  final KeycloakSession session = mock(KeycloakSession.class);
  final RealmModel realm = mock(RealmModel.class);
  final UserModel user = mock(UserModel.class);
  final CredentialContext context = new CredentialContext(session, realm, user);

  private final AtomicInteger codeSequence = new AtomicInteger(100000);
  private boolean mailServerDown;
  private String storedCredentialData;
  private String storedSecretData;

  MailOtpLoginFixture() {
    when(user.getEmail()).thenReturn(EMAIL);
    when(user.getId()).thenReturn("user-1");

    otpService = new MemoryOtpService(length -> String.valueOf(codeSequence.incrementAndGet()),
        clock, null);

    var provider = mock(MailOtpCredentialProvider.class);
    when(provider.getDefaultCredential(any(), any(), any())).thenAnswer(invocation -> read());
    doAnswer(invocation -> {
      write(invocation.getArgument(1));
      return null;
    }).when(provider).updateCredential(any(), any());
    credentialService = new MailOtpCredentialService(provider, clock);

    mailSender = (otp, ctx) -> {
      if (mailServerDown) {
        throw new MailSendingException("smtp down", null);
      }
      mailedCodes.add(otp);
    };

    var initial = MailOtpCredentialModel.createOtpModel(
        new Otp(MailOtpCredentialModel.INVALIDATED, 900, 0L, EMAIL, 0), clock, true);
    write(initial);
  }

  OtpMailThrottle defaultThrottle() {
    return OtpMailThrottle.fromConfig(clock, null);
  }

  OtpMailThrottle throttleFromConfig(AuthenticatorConfigModel config) {
    return OtpMailThrottle.fromConfig(clock, config);
  }

  void mailServerDown(boolean down) {
    this.mailServerDown = down;
  }

  String lastMailedCode() {
    return mailedCodes.get(mailedCodes.size() - 1).getCode();
  }

  MailOtpCredentialModel read() {
    var stored = new CredentialModel();
    stored.setCredentialData(storedCredentialData);
    stored.setSecretData(storedSecretData);
    stored.setType(MailOtpCredentialModel.TYPE);
    return MailOtpCredentialModel.createFromCredentialModel(stored);
  }

  String storedCredentialData() {
    return storedCredentialData;
  }

  void overwriteStoredCredentialData(String credentialData) {
    this.storedCredentialData = credentialData;
  }

  private void write(MailOtpCredentialModel model) {
    storedCredentialData = model.getCredentialData();
    storedSecretData = model.getSecretData();
  }

  static final class MutableClock extends Clock {

    private Instant now;

    MutableClock(Instant start) {
      this.now = start;
    }

    void advance(Duration duration) {
      now = now.plus(duration);
    }

    void advanceSeconds(long seconds) {
      advance(Duration.ofSeconds(seconds));
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
