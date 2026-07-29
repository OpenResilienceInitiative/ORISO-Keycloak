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
  public void rendersReadableSelectableOtpInOrisoEmailDesignWithoutClientSideScript()
      throws Exception {
    String html = renderHtml("de", "123456", 15);

    assertThat(html)
        .contains("<html lang=\"de\">")
        .contains(">ORISO</td>")
        .contains("Ihr 2FA-Code")
        .contains("aria-label=\"Ihr 2FA-Code: 123456\"")
        .contains(">123456</")
        .contains("user-select:all")
        .contains("Zum Kopieren den Code doppelklicken oder gedrückt halten.")
        .contains("15 Minuten")
        .doesNotContain("Onlineberatung")
        .doesNotContain("data:image")
        .doesNotContain("<script")
        .doesNotContain("onclick=");
  }

  @Test
  public void rendersEnglishCopyForEnglishRecipients() throws Exception {
    String html = renderHtml("en", "654321", 10);

    assertThat(html)
        .contains("<html lang=\"en\">")
        .contains("Your 2FA code")
        .contains("aria-label=\"Your 2FA code: 654321\"")
        .contains(">654321</")
        .contains("Double-click or press and hold the code to copy it.")
        .contains("10 minutes")
        .doesNotContain("Ihr 2FA-Code")
        .doesNotContain("Onlineberatung");
  }

  private String renderHtml(String language, String otp, int ttl) throws Exception {
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

    Map<String, Object> model = new HashMap<>();
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
