/**
 * Created on May 27, 2020 by Radoslav Filipov
 */
package com.secrets.vault.shell;

import static com.secrets.vault.model.ShellCommand.fromValue;
import static java.lang.System.out;

import java.io.File;
import java.io.IOException;
import java.text.MessageFormat;
import java.util.Scanner;
import java.util.Set;

import com.secrets.vault.SecretsVaultUtils;
import com.secrets.vault.model.FileEventFactory;
import com.secrets.vault.model.ShellCommand;
import com.secrets.vault.validation.NonBlankInputValidator;

/**
 * The class is used to process input coming from the {@link System#in}
 *
 * @author Filipov, Radoslav
 */
public final class ShellProcessor {

  private static final Set<String> TERMINATION_COMMANDS = Set.of("exit", "quit", "q");

  private static NonBlankInputValidator nonBlankInputValidator = new NonBlankInputValidator();

  private ShellProcessor() {
    // this class should not be instantiated
  }

  /**
   * Processes the given input until termination command is given
   *
   * @throws IOException
   */
  public static void processInput() throws IOException {
    out.println(SecretsVaultUtils.CURRENT_USER + " vault");
    out.print("\tcommand: ");

    Scanner scanner = SecretsVaultUtils.getScanner();
    ShellCommand enumCommand = fromValue(scanner.next());
    while (!TERMINATION_COMMANDS.contains(enumCommand.toString())) {
      out.print("\tfilename: ");
      String filename = scanner.next();
      nonBlankInputValidator.validate(filename);

      File fileSubject = new File(filename);
      FileEventFactory.getFileEvent(enumCommand).onEvent(fileSubject);

      out.print(MessageFormat.format("\t{0}\n\tcommand: ", "-".repeat(50)));
      enumCommand = fromValue(scanner.next());
    }
    scanner.close();
  }

}
