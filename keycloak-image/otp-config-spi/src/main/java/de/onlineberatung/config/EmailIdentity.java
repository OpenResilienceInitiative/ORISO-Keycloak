package de.onlineberatung.config;

import java.util.function.Function;

/** Required installation identity for the generated Keycloak mail theme. */
public final class EmailIdentity {

  public static final String PRODUCT_ENV = "EMAIL_BRANDING_NAME";
  public static final String LEGAL_ORGANISATION_ENV = "EMAIL_LEGAL_ORGANISATION_NAME";

  private EmailIdentity() {}

  public static void requireFromEnvironment(Function<String, String> env) {
    require(PRODUCT_ENV, env.apply(PRODUCT_ENV));
    require(LEGAL_ORGANISATION_ENV, env.apply(LEGAL_ORGANISATION_ENV));
  }

  static String require(String name, String configured) {
    String value = configured == null ? "" : configured.trim();
    if (!value.isEmpty() && !value.contains("${") && !value.contains("\r")
        && !value.contains("\n")) {
      return value;
    }
    throw new IllegalStateException(name + " must be set to this installation's name");
  }
}
