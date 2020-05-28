/**
 * Created on May 27, 2020 by Radoslav Filipov
 */
package com.secrets.vault.shell;

import static java.lang.System.out;

import java.io.File;
import java.io.IOException;
import java.util.Scanner;
import java.util.Set;

import com.secrets.vault.SecretsVaultUtils;
import com.secrets.vault.model.FileEventFactory;
import com.secrets.vault.model.FileShellCommand;
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
    String command = scanner.next();
    nonBlankInputValidator.validate(command);
    while (!TERMINATION_COMMANDS.contains(command)) {
      out.print("\tfilename: ");
      String filename = scanner.next();
      nonBlankInputValidator.validate(filename);

      File fileSubject = new File(filename);
      FileEventFactory.getFileEvent(FileShellCommand.fromValue(command)).onEvent(fileSubject);

      out.print("\n\tcommand: ");
      command = scanner.next();
      nonBlankInputValidator.validate(command);
    }
    scanner.close();
  }

}
