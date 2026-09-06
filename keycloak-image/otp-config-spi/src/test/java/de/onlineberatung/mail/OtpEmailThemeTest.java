package de.onlineberatung.mail;

import static org.assertj.core.api.Assertions.assertThat;

import freemarker.core.HTMLOutputFormat;
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

public class OtpEmailThemeTest {

  @Test
  public void omitsTheWholeLogoCellWhenNoImageIsConfigured() throws Exception {
    assertThat(renderHtml("de", "123456", 15)).doesNotContain("<img").doesNotContain("padding-right:12px");
  }

  @Test
  public void onlyRendersLogoImagesHostedByTheApplication() throws Exception {
    Map<String, String> env = Map.of(
        "env.ORISO_APP_URL", "https://predev.oriso.org",
        "env.ORISO_LOGO_URL", "https://predev.oriso.org/service/tenant/public/branding/0/logo");
    assertThat(renderHtml("de", "123456", 15, true, env))
        .contains("src=\"https://predev.oriso.org/service/tenant/public/branding/0/logo\"");
    assertThat(renderHtml("de", "123456", 15, true, Map.of(
        "env.ORISO_APP_URL", "https://predev.oriso.org",
        "env.ORISO_LOGO_URL", "https://predev.oriso.org.evil.example/logo.png")))
        .doesNotContain("<img");
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
  public void rendersWithoutThemeProperties() throws Exception {
    // The Helm chart mounts email/{html,messages,text} and no theme.properties,
    // so every theme lookup carries its own default. Without that, the button
    // would render with an empty background-color — that is, no button.
    String html = renderHtml("de", "123456", 15, false);

    assertThat(html)
        .contains("<!DOCTYPE html>")
        .contains("123456")
        .doesNotContain("background-color:;")
        .doesNotContain("href=\"\"");
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
    return renderHtml(language, otp, ttl, withThemeProperties, Map.of());
  }

  private String renderHtml(String language, String otp, int ttl, boolean withThemeProperties,
      Map<String, String> environment) throws Exception {
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
    configuration.setOutputFormat(HTMLOutputFormat.INSTANCE);
    configuration.setDirectoryForTemplateLoading(emailTheme.resolve("html").toFile());

    Properties themeProperties = new Properties();
    try (var reader =
        Files.newBufferedReader(
            emailTheme.resolve("theme.properties"), StandardCharsets.UTF_8)) {
      themeProperties.load(reader);
    }

    themeProperties.replaceAll((key, value) ->
        org.keycloak.common.util.StringPropertyReplacer.replaceProperties(
            value.toString(), environment::get));

    Map<String, Object> model = new HashMap<>();
    if (withThemeProperties) {
      model.put("properties", themeProperties);
    }
    model.put("otp", otp);
    model.put("ttl", ttl);
    model.put("locale", Locale.forLanguageTag(language));
    model.put("msg", messageLookup(messages));
    model.put("kcSanitize", passthroughSanitizer());

    StringWriter output = new StringWriter();
    configuration.getTemplate("otp-email.ftl").process(model, output);
    return output.toString();
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
