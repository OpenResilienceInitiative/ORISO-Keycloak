package de.onlineberatung.otp;

public interface OtpService {

  ValidationResult validate(String currentCode, Otp otp);

  Otp createOtp(String emailAddress);

  /**
   * How many wrong codes a single code tolerates before it is spent.
   *
   * <p>The caller needs the number to know that THIS wrong code was the last one, so the lockout
   * starts with it rather than one submission later — the submission in between is exactly where
   * a new code could be requested and the limit walked around.
   */
  int maxFailedValidations();

}
