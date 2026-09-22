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

  // Same placeholder set as UserService/Helm: RFC 2606/6761 documentation and invalid domains
  // (the host or any subdomain) plus the Helm values template's `your-domain`.
  private static final List<String> RESERVED_DOMAINS =
      List.of("example.com", "example.org", "example.net", "example.test", "invalid");

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
    if (value.toLowerCase(Locale.ROOT).contains("your-domain")) {
      return true;
    }
    String host = URI.create(value).getHost().toLowerCase(Locale.ROOT);
    return RESERVED_DOMAINS.stream()
        .anyMatch(domain -> host.equals(domain) || host.endsWith("." + domain));
  }
}
