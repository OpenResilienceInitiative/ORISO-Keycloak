package de.onlineberatung.otp;

import org.keycloak.common.util.SecretGenerator;

public class RandomDigitsCodeGenerator implements OtpGenerator {

  @Override
  public String generate(int length) {
    return SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);
  }

}
