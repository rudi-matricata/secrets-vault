/**
 * Created on May 27, 2020 by Radoslav Filipov
 */
package com.secrets.vault.model;

import com.secrets.vault.shell.ShellCommand;

/**
 * @author Filipov, Radoslav
 */
public final class FileEventFactory {

  private FileEventFactory() {
    // this class should not be instantiated
  }

  /**
   * Returns file event object of the corresponding command
   *
   * @param command
   * @return fileEvent
   */
  public static FileEvent getFileEvent(ShellCommand command) {
    switch (command) {
      case DECRYPT:
        return new FileDecryptEvent();
      case ENCRYPT:
        return new FileEncryptEvent();

      default:
        throw new IllegalArgumentException("Illegal value provided: " + command.name());

    }
  }

}
