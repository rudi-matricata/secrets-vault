/**
 * Created on May 27, 2020 by Radoslav Filipov
 */
package com.secrets.vault.model;

/**
 * @author Filipov, Radoslav
 */
public final class FileEventFactory {

  private FileEventFactory() {
    // this class should not be instantiated
  }

  public static FileEvent getFileEvent(FileShellCommand command) {
    switch (command) {
      case READ:
        return new FileReadEvent();
      case CREATE:
        return new FileCreateEvent();

      default:
        throw new IllegalArgumentException("Illegal value provided: " + command.name());

    }
  }

}
