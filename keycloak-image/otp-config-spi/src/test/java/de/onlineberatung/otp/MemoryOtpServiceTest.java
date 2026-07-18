package de.onlineberatung.otp;

import static de.onlineberatung.otp.ValidationResult.INVALID;
import static de.onlineberatung.otp.ValidationResult.NOT_PRESENT;
import static de.onlineberatung.otp.ValidationResult.TOO_MANY_FAILED_ATTEMPTS;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.HashMap;
import org.junit.Before;
import org.junit.Test;
import org.keycloak.models.AuthenticatorConfigModel;

public class MemoryOtpServiceTest {

  private OtpGenerator otpGenerator;
  private Clock fixed;
  private MemoryOtpService memoryOtpService;

  @Before
  public void setUp() {
    fixed = Clock.fixed(LocalDateTime.of(2022, 2, 3, 13, 13, 0).toInstant(ZoneOffset.UTC),
        ZoneId.of("UTC"));
    otpGenerator = mock(OtpGenerator.class);
    memoryOtpService = new MemoryOtpService(otpGenerator, fixed, null);
  }

  @Test
  public void should_create_otp_with_default_ttl_and_expiry() {
    when(otpGenerator.generate(6)).thenReturn("123456");

    var otp = memoryOtpService.createOtp("hk@test.de");

    var expected = new Otp("123456", 900, 1643894880000L, "hk@test.de", 0);
    verify(otpGenerator).generate(6);
    assertThat(otp).isEqualTo(expected);
  }

  @Test
  public void should_use_auth_config_if_given() {
    var authConfig = mock(AuthenticatorConfigModel.class);
    var internalConfig = new HashMap<String, String>();
    when(authConfig.getConfig()).thenReturn(internalConfig);
    internalConfig.put("ttl", "500");
    internalConfig.put("length", "8");
    memoryOtpService = new MemoryOtpService(otpGenerator, fixed,
        authConfig);
    when(otpGenerator.generate(8)).thenReturn("12345678");

    var otp = memoryOtpService.createOtp("hk@test.de");

    var expected = new Otp("12345678", 500, 1643894480000L, "hk@test.de", 0);
    assertThat(otp).isEqualTo(expected);
  }

  @Test
  public void validate_should_be_valid_if_otp_equals_current_and_is_not_expired() {
    var valid = new Otp("4711", 300, fixed.millis() + 1000, null, 0);

    var result = memoryOtpService.validate("4711", valid);

    assertThat(result).isEqualTo(ValidationResult.VALID);
  }

  @Test
  public void validate_should_be_not_present_if_otp_was_invalidated() {
    var invalidated = new Otp("INVALIDATED", 300, fixed.millis() + 1000, null, 0);

    var result = memoryOtpService.validate("4711", invalidated);

    assertThat(result).isEqualTo(NOT_PRESENT);
  }

  @Test
  public void validate_should_return_expired_if_otp_is_expired() {
    var expired = new Otp("4711", 3000L, fixed.millis() - 1000, null, 0);

    var result = memoryOtpService.validate("4711", expired);

    assertThat(result).isEqualTo(ValidationResult.EXPIRED);
  }

  @Test
  public void validate_should_be_invalid_if_stored_otp_code_does_not_equal_current() {
    var invalid = new Otp("1234", 300, fixed.millis() + 1000, null, 0);

    var result = memoryOtpService.validate("4711", invalid);

    assertThat(result).isEqualTo(INVALID);
  }

  @Test
  public void validate_should_be_invalid_on_empty_or_null_current_code() {
    var invalid = new Otp("1234", 300, fixed.millis() + 1000, null, 0);

    assertThat(memoryOtpService.validate("", invalid)).isEqualTo(INVALID);
    assertThat(memoryOtpService.validate(null, invalid)).isEqualTo(INVALID);
  }

  @Test
  public void validate_should_not_be_valid_if_otp_has_too_many_failed_attempts() {
    var tooManyAttempts = new Otp("1234", 300, fixed.millis() + 1000, null, 3);

    assertThat(memoryOtpService.validate("4", tooManyAttempts)).isEqualTo(TOO_MANY_FAILED_ATTEMPTS);
  }

  @Test
  public void validate_should_not_be_valid_if_too_may_attempts_were_made_even_if_code_is_valid() {
    var tooManyFailed = new Otp("4711", 300, fixed.millis() + 1000, null, 3);

    var result = memoryOtpService.validate("4711", tooManyFailed);

    assertThat(result).isEqualTo(TOO_MANY_FAILED_ATTEMPTS);
  }
}
