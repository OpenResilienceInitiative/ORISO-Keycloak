package de.onlineberatung.mail;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import freemarker.core.HTMLOutputFormat;
import freemarker.core.InvalidReferenceException;
import freemarker.core.PlainTextOutputFormat;
import freemarker.template.Configuration;
import freemarker.template.SimpleScalar;
import freemarker.template.TemplateMethodModelEx;
import freemarker.template.TemplateModelException;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.MessageFormat;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import org.junit.Test;
import org.keycloak.common.util.StringPropertyReplacer;

public class OtpEmailThemeTest {

  private static final String APP_ORIGIN = "https://dev.example.org";

  @Test
  public void rendersTheOtpInTheOrisoEmailDesignWithoutClientSideScript() throws Exception {
    String html = renderHtml("de", "123456", 15);

    assertThat(html)
        .contains("<html lang=\"de\">")
        .contains("Ihr Einmalcode")
        .contains("123456")
        .contains("Geben Sie diesen Code im Anmeldefenster ein.")
        .doesNotContain("data:image")
        .doesNotContain("<script")
        .doesNotContain("onclick=");
  }

  @Test
  public void usesTheDesignSystemSkeletonRatherThanItsOwn() throws Exception {
    String html = renderHtml("de", "123456", 15);

    // The template is generated from the ORISO e-mail design system
    // (ORISO-Frontend `npm run emails:keycloak`), so it has to carry the design
    // system's canvas and column and not the skeleton this theme used to build
    // for itself.
    assertThat(html)
        .contains("#f2efef")
        .contains("width=\"600\"")
        .contains("Inter")
        .doesNotContain("#f4f6fa")
        .doesNotContain("#0f3b8f");
  }

  @Test
  public void offersNoButtonBackToTheLoginScreen() throws Exception {
    // The recipient is already in the window that asked for the code. A link
    // back to the login screen would compete with the flow they are halfway
    // through.
    assertThat(renderHtml("de", "123456", 15)).doesNotContain("Zur Anmeldung");
  }

  @Test
  public void carriesNoUnsubscribeLink() throws Exception {
    // A one-time code is in the security class (ADR-019): nothing switches it
    // off, so the footer must not pretend otherwise.
    assertThat(renderHtml("de", "123456", 15)).doesNotContain("abbestellen</a>");
  }

  @Test
  public void refusesToRenderWithoutThemeProperties() {
    // Links carry no default any more: without the theme's properties the render
    // fails instead of silently pointing at some other environment.
    assertThatThrownBy(() -> renderHtml("de", "123456", 15, false))
        .isInstanceOf(InvalidReferenceException.class);
  }

  @Test
  public void otpFooterLinksPointAtTheConfiguredAppOrigin() throws Exception {
    String html = renderHtml("de", "123456", 15);
    String text = render("text", "otp-email.ftl", "de", otpModel("123456", 15), true);

    for (String mail : List.of(html, text)) {
      assertThat(mail)
          .contains(APP_ORIGIN + "/datenschutz")
          .contains(APP_ORIGIN + "/impressum")
          .doesNotContain("${env.")
          .doesNotContain("oriso.org");
    }
  }

  @Test
  public void passwordResetFooterLinksPointAtTheConfiguredAppOrigin() throws Exception {
    Map<String, Object> model = new HashMap<>();
    model.put("link", "https://auth.example.org/reset?key=abc");
    model.put("linkExpiration", 5);
    model.put("linkExpirationFormatter", (TemplateMethodModelEx) args -> "5 Minuten");
    String html = render("html", "password-reset.ftl", "de", model, true);
    String text = render("text", "password-reset.ftl", "de", model, true);

    for (String mail : List.of(html, text)) {
      assertThat(mail)
          .contains(APP_ORIGIN + "/profile/settings")
          .contains(APP_ORIGIN + "/datenschutz")
          .contains(APP_ORIGIN + "/impressum")
          .contains(APP_ORIGIN + "/profile/settings/notifications")
          .doesNotContain("${env.")
          .doesNotContain("oriso.org");
    }
  }

  @Test
  public void rendersEnglishCopyForEnglishRecipients() throws Exception {
    String html = renderHtml("en", "654321", 10);

    assertThat(html)
        .contains("<html lang=\"en\">")
        .contains("Your one-time code")
        .contains("654321")
        .contains("Enter this code in the sign-in window.")
        .doesNotContain("Ihr Einmalcode");
  }

  private String renderHtml(String language, String otp, int ttl) throws Exception {
    return renderHtml(language, otp, ttl, true);
  }

  private String renderHtml(String language, String otp, int ttl, boolean withThemeProperties)
      throws Exception {
    return render("html", "otp-email.ftl", language, otpModel(otp, ttl), withThemeProperties);
  }

  private static Map<String, Object> otpModel(String otp, int ttl) {
    Map<String, Object> model = new HashMap<>();
    model.put("otp", otp);
    model.put("ttl", ttl);
    return model;
  }

  private String render(
      String format,
      String template,
      String language,
      Map<String, Object> templateModel,
      boolean withThemeProperties)
      throws Exception {
    Path emailTheme = Path.of(System.getProperty("basedir")).resolve("../themes/oriso/email");
    Properties messages = new Properties();
    try (var reader =
        Files.newBufferedReader(
            emailTheme.resolve("messages/messages_" + language + ".properties"),
            StandardCharsets.UTF_8)) {
      messages.load(reader);
    }

    Configuration configuration = new Configuration(Configuration.VERSION_2_3_32);
    configuration.setDefaultEncoding(StandardCharsets.UTF_8.name());
    configuration.setOutputFormat(
        "html".equals(format) ? HTMLOutputFormat.INSTANCE : PlainTextOutputFormat.INSTANCE);
    configuration.setDirectoryForTemplateLoading(emailTheme.resolve(format).toFile());

    Map<String, Object> model = new HashMap<>(templateModel);
    if (withThemeProperties) {
      model.put("properties", themePropertiesAsKeycloakResolvesThem(emailTheme));
    }
    model.put("locale", Locale.forLanguageTag(language));
    model.put("msg", messageLookup(messages));
    model.put("kcSanitize", passthroughSanitizer());

    StringWriter output = new StringWriter();
    configuration.getTemplate(template).process(model, output);
    return output.toString();
  }

  /**
   * Keycloak's theme manager runs every theme.properties value through StringPropertyReplacer
   * with the environment as resolver (DefaultThemeManager.ExtendingTheme#substituteProperties),
   * so `${env.ORISO_APP_BASE_URL}` becomes the container's value. Same replacer here.
   */
  private static Properties themePropertiesAsKeycloakResolvesThem(Path emailTheme)
      throws Exception {
    Properties themeProperties = new Properties();
    try (var reader =
        Files.newBufferedReader(emailTheme.resolve("theme.properties"), StandardCharsets.UTF_8)) {
      themeProperties.load(reader);
    }
    Map<String, String> env = Map.of("env.ORISO_APP_BASE_URL", APP_ORIGIN);
    for (String key : themeProperties.stringPropertyNames()) {
      themeProperties.setProperty(
          key,
          StringPropertyReplacer.replaceProperties(themeProperties.getProperty(key), env::get));
    }
    return themeProperties;
  }

  private TemplateMethodModelEx messageLookup(Properties messages) {
    return arguments -> {
      if (arguments.isEmpty()) {
        throw new TemplateModelException("Message key is required");
      }
      String key = arguments.get(0).toString();
      String pattern = messages.getProperty(key, key);
      Object[] values =
          arguments.subList(1, arguments.size()).stream().map(Object::toString).toArray();
      return new SimpleScalar(MessageFormat.format(pattern, values));
    };
  }

  @SuppressWarnings({"rawtypes", "unchecked"})
  private TemplateMethodModelEx passthroughSanitizer() {
    return (List arguments) ->
        new SimpleScalar(arguments.isEmpty() ? "" : arguments.get(0).toString());
  }
}
