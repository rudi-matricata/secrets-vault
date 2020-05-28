/**
 * Created on May 27, 2020 by Radoslav Filipov
 */
package com.secrets.vault.shell;

import static com.secrets.vault.SecretsVaultUtils.OUTPUT_PATTERN;
import static java.lang.System.out;
import static java.text.MessageFormat.format;

import java.io.File;
import java.io.IOException;
import java.util.Scanner;

import com.secrets.vault.SecretsVaultUtils;
import com.secrets.vault.model.FileEventFactory;
import com.secrets.vault.model.FileShellCommand;

/**
 * The class is used to process input coming from the {@link System#in}
 *
 * @author Filipov, Radoslav
 */
public final class ShellProcessor {

  private ShellProcessor() {
    // this class should not be instantiated
  }

  public static void processInput() throws IOException {
    out.print(format(OUTPUT_PATTERN, "command"));

    Scanner scanner = SecretsVaultUtils.getScanner();
    String command = scanner.next();
    while (!"exit".equals(command)) {
      out.print(format(OUTPUT_PATTERN, "filename"));
      File fileSubject = new File(scanner.next());

      FileEventFactory.getFileEvent(FileShellCommand.fromValue(command)).onEvent(fileSubject);

      out.print("\n" + format(OUTPUT_PATTERN, "command"));
      command = scanner.next();
    }
    scanner.close();
  }

}
