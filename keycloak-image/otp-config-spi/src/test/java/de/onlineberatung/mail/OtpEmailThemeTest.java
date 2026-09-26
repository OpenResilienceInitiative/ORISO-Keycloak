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

  private static final String APP_ORIGIN = "https://app.oriso-test.internal";

  // --- Logo -------------------------------------------------------------------
  //
  // Mail clients block data: URIs, so the logo is referenced by an absolute URL on
  // the app's own origin. TenantService serves the Träger's detailed logo (Admin ->
  // Appearance -> "Logo") at /service/tenant/public/branding/{tenantId}/logo.

  private static final String TENANT_LOGO =
      APP_ORIGIN + "/service/tenant/public/branding/7/logo";
  private static final String PLATFORM_LOGO =
      APP_ORIGIN + "/service/tenant/public/branding/logo";

  @Test
  public void rendersOtpAndResetInEveryAppLanguage() throws Exception {
    Path emailTheme = Path.of(System.getProperty("basedir")).resolve("../themes/oriso/email");
    Properties theme = new Properties();
    try (var reader = Files.newBufferedReader(emailTheme.resolve("theme.properties"), StandardCharsets.UTF_8)) {
      theme.load(reader);
    }
    assertThat(theme.getProperty("locales")).isEqualTo("de,en,fr,ru,ti,tr");

    for (String language : List.of("de", "en", "fr", "ru", "ti", "tr")) {
      Properties messages = new Properties();
      try (var reader = Files.newBufferedReader(
          emailTheme.resolve("messages/messages_" + language + ".properties"), StandardCharsets.UTF_8)) {
        messages.load(reader);
      }
      Map<String, Object> reset = new HashMap<>();
      reset.put("link", APP_ORIGIN + "/reset?key=abc");
      reset.put("linkExpiration", 5);
      reset.put("linkExpirationFormatter", (TemplateMethodModelEx) args -> "5 minutes");

      for (String format : List.of("html", "text")) {
        String otp = render(format, "otp-email.ftl", language, otpModel("123456", 15), true);
        String passwordReset = render(format, "password-reset.ftl", language, reset, true);
        assertThat(otp).as(language + " OTP " + format)
            .contains(messages.getProperty("orisoOtpHeadline"), "123456", APP_ORIGIN + "/datenschutz")
            .doesNotContain("${env.");
        assertThat(passwordReset).as(language + " reset " + format)
            .contains(messages.getProperty("orisoResetHeadline"), APP_ORIGIN + "/reset?key=abc")
            .doesNotContain("${env.");
      }
    }
  }

  @Test
  public void showsTheLogoOfTheRecipientsTraegerInBothMails() throws Exception {
    for (String template : List.of("otp-email.ftl", "password-reset.ftl")) {
      String html = renderHtmlFor(template, Map.of(), Map.of("tenantId", "7"));

      assertThat(logoImage(html))
          .as(template)
          .contains("src=\"" + TENANT_LOGO + "\"")
          .contains("width=\"36\"")
          .contains("height=\"36\"")
          .contains("border:0");
    }
  }

  @Test
  public void showsTheBrandNameBesideTheLogo() throws Exception {
    // Frank, 2026-09-23: logo AND name, as before the logo-only iteration.
    for (String template : List.of("otp-email.ftl", "password-reset.ftl")) {
      String html = renderHtmlFor(template, Map.of(), Map.of("tenantId", "7"));

      assertThat(html).as(template).contains(">Online-Beratung</td>");
      assertThat(html.indexOf("<img")).as(template).isLessThan(html.indexOf(">Online-Beratung</td>"));
    }
  }

  @Test
  public void marksTheLogoDecorativeSoAFailedImageDoesNotRepeatTheName() throws Exception {
    // The name already stands beside the logo: alt="" and no styled alt text.
    String image = logoImage(renderHtmlFor("otp-email.ftl", Map.of(), Map.of("tenantId", "7")));

    assertThat(image).contains(" alt=\"\"").doesNotContain("Online-Beratung");
    assertThat(image).doesNotContain("font-family");
  }

  @Test
  public void hidesAFailedLogoInsteadOfShowingABrokenImage() throws Exception {
    // Chromium draws ::after only on an image that failed to load; the overlay in
    // the canvas colour hides the broken-image icon and adds no text.
    String html = renderHtmlFor("otp-email.ftl", Map.of(), Map.of("tenantId", "7"));

    assertThat(html)
        .contains("img[alt=\"\"]::after{content:\"\";")
        .doesNotContain("content:attr(alt)");
  }

  @Test
  public void fallsBackToThePlatformLogoWhenTheRecipientHasNoTraeger() throws Exception {
    for (Map<String, String> attributes :
        List.of(Map.<String, String>of(), Map.of("tenantId", "0"))) {
      String html =
          renderHtmlFor("otp-email.ftl", Map.of("env.ORISO_LOGO_URL", PLATFORM_LOGO), attributes);

      assertThat(logoImage(html)).as(attributes.toString()).contains("src=\"" + PLATFORM_LOGO + "\"");
    }
  }

  @Test
  public void rendersOnlyTheTextWordmarkWhenNoLogoIsConfigured() throws Exception {
    for (String template : List.of("otp-email.ftl", "password-reset.ftl")) {
      String html = renderHtmlFor(template, Map.of(), Map.of());

      assertThat(html)
          .as(template)
          .doesNotContain("<img")
          .doesNotContain("padding-right:12px")
          .contains(">Online-Beratung</td>");
    }
  }

  @Test
  public void neverReferencesALogoOutsideTheAppOrigin() throws Exception {
    // A foreign host would learn who opened the mail and when.
    for (String foreign :
        List.of(
            "https://app.oriso-test.internal.evil.example/logo.png",
            "http://app.oriso-test.internal/logo.png",
            "https://tracker.example.net/pixel.png")) {
      String html =
          renderHtmlFor("otp-email.ftl", Map.of("env.ORISO_LOGO_URL", foreign), Map.of());

      assertThat(html).as(foreign).doesNotContain("<img");
    }
  }

  @Test
  public void ignoresATenantIdThatIsNotAPositiveNumber() throws Exception {
    for (String tenantId : List.of("0", "-3", "7/../../x", "7\"onerror=\"x", "")) {
      String html = renderHtmlFor("otp-email.ftl", Map.of(), Map.of("tenantId", tenantId));

      assertThat(html).as(tenantId).doesNotContain("<img").doesNotContain("onerror");
    }
  }

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
  public void passwordResetFooterHasLegalLinksButNoUnsubscribeControls() throws Exception {
    Map<String, Object> model = new HashMap<>();
    model.put("link", "https://auth.oriso-test.internal/reset?key=abc");
    model.put("linkExpiration", 5);
    model.put("linkExpirationFormatter", (TemplateMethodModelEx) args -> "5 Minuten");
    String html = render("html", "password-reset.ftl", "de", model, true);
    String text = render("text", "password-reset.ftl", "de", model, true);

    for (String mail : List.of(html, text)) {
      assertThat(mail)
          .contains(APP_ORIGIN + "/datenschutz")
          .contains(APP_ORIGIN + "/impressum")
          .doesNotContain(APP_ORIGIN + "/profile/settings")
          .doesNotContain(APP_ORIGIN + "/profile/settings/notifications")
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

  private String renderHtmlFor(
      String template, Map<String, String> env, Map<String, String> userAttributes)
      throws Exception {
    Map<String, Object> model = otpModel("123456", 15);
    model.put("link", "https://auth.oriso-test.internal/reset?key=abc");
    model.put("linkExpiration", 5);
    model.put("linkExpirationFormatter", (TemplateMethodModelEx) args -> "5 Minuten");
    // Keycloak puts the recipient in as `user` (ProfileBean): `attributes` holds the
    // first value of every user attribute, including UserService's `tenantId`.
    model.put("user", Map.of("attributes", userAttributes));
    return render("html", template, "de", model, true, env);
  }

  /** The logo `<img>` tag, or an empty string when the mail has none. */
  private static String logoImage(String html) {
    int start = html.indexOf("<img");
    return start < 0 ? "" : html.substring(start, html.indexOf('>', start) + 1);
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
    return render(format, template, language, templateModel, withThemeProperties, Map.of());
  }

  private String render(
      String format,
      String template,
      String language,
      Map<String, Object> templateModel,
      boolean withThemeProperties,
      Map<String, String> extraEnv)
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
      model.put("properties", themePropertiesAsKeycloakResolvesThem(emailTheme, extraEnv));
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
  private static Properties themePropertiesAsKeycloakResolvesThem(
      Path emailTheme, Map<String, String> extraEnv) throws Exception {
    Properties themeProperties = new Properties();
    try (var reader =
        Files.newBufferedReader(emailTheme.resolve("theme.properties"), StandardCharsets.UTF_8)) {
      themeProperties.load(reader);
    }
    Map<String, String> env = new HashMap<>(extraEnv);
    env.put("env.ORISO_APP_BASE_URL", APP_ORIGIN);
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
