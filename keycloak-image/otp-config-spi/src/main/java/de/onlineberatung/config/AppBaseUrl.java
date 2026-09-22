package de.onlineberatung.config;

import java.net.URI;
import java.util.List;
import java.util.Locale;
import java.util.function.Function;

/**
 * The app origin the `oriso` email theme builds its links from (theme.properties reads it as
 * `${env.ORISO_APP_BASE_URL}`). Keycloak leaves an unset `${env.X}` as literal text, so without
 * this check every mail would carry broken links instead of failing loudly.
 */
public final class AppBaseUrl {

  public static final String ENV_NAME = "ORISO_APP_BASE_URL";

  // Placeholders from the Helm values template; a real deployment never uses them.
  private static final List<String> PLACEHOLDERS = List.of("your-domain", "example.com");

  private AppBaseUrl() {}

  public static String requireFromEnvironment(Function<String, String> env) {
    return require(env.apply(ENV_NAME));
  }

  /** Returns the trimmed origin, or throws naming {@link #ENV_NAME}. */
  public static String require(String configured) {
    String value = configured == null ? "" : configured.trim();
    if (isAbsoluteOrigin(value) && !isPlaceholder(value)) {
      return value;
    }
    throw new IllegalStateException(
        ENV_NAME
            + " must be this environment's absolute app origin (http(s)://host[:port], no path,"
            + " no trailing slash, no placeholder); the oriso email theme builds every mail link"
            + " from it. Got: '"
            + configured
            + "'");
  }

  private static boolean isAbsoluteOrigin(String value) {
    try {
      URI uri = new URI(value);
      return ("http".equals(uri.getScheme()) || "https".equals(uri.getScheme()))
          && uri.getHost() != null
          && !uri.getHost().isBlank()
          && uri.getUserInfo() == null
          && (uri.getRawPath() == null || uri.getRawPath().isEmpty())
          && uri.getRawQuery() == null
          && uri.getRawFragment() == null;
    } catch (Exception e) {
      return false;
    }
  }

  private static boolean isPlaceholder(String value) {
    String lower = value.toLowerCase(Locale.ROOT);
    return PLACEHOLDERS.stream().anyMatch(lower::contains);
  }
}
