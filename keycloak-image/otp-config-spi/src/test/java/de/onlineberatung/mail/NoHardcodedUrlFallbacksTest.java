package de.onlineberatung.mail;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import org.junit.Test;

/**
 * Team rule: a deployed service never invents a URL. The theme ships in the image, so a host in
 * it becomes every environment's host. Links must come from ORISO_APP_BASE_URL.
 */
public class NoHardcodedUrlFallbacksTest {

  private static final Pattern ORISO_HOST = Pattern.compile("oriso\\.org");
  // FreeMarker default (`!'https://…'`) or properties literal (`=https://…`).
  private static final Pattern URL_DEFAULT = Pattern.compile("!\\s*['\"]https?://|=\\s*https?://");

  @Test
  public void themeFilesNeverNameAHostOrDefaultAUrl() throws IOException {
    Path themes = Path.of(System.getProperty("basedir")).resolve("../themes");
    List<String> violations;
    try (Stream<Path> files = Files.walk(themes)) {
      violations =
          files
              .filter(Files::isRegularFile)
              .flatMap(NoHardcodedUrlFallbacksTest::violationsIn)
              .collect(Collectors.toList());
    }
    assertThat(violations).isEmpty();
  }

  @Test
  public void everyLinkPropertyDerivesFromTheEnvironment() throws IOException {
    Path properties =
        Path.of(System.getProperty("basedir")).resolve("../themes/oriso/email/theme.properties");
    List<String> linkLines =
        Files.readAllLines(properties).stream()
            .filter(line -> line.matches("oriso\\w*Url=.*") && !line.startsWith("orisoLogoUrl="))
            .collect(Collectors.toList());

    assertThat(linkLines)
        .isNotEmpty()
        .allSatisfy(line -> assertThat(line).contains("=${env.ORISO_APP_BASE_URL}"));
  }

  private static Stream<String> violationsIn(Path file) {
    try {
      List<String> lines = Files.readAllLines(file);
      return IntStream.range(0, lines.size())
          .filter(
              i ->
                  ORISO_HOST.matcher(lines.get(i)).find()
                      || URL_DEFAULT.matcher(lines.get(i)).find())
          .mapToObj(i -> file + ":" + (i + 1));
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
  }
}
