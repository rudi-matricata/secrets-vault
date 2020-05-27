/**
 * Created on May 27, 2020 by Radoslav Filipov
 */
package com.secrets.vault.model;

/**
 * @author Filipov, Radoslav
 */
public enum FileShellCommand {

  READ("read"), CREATE("create");

  private String name;

  private FileShellCommand(String name) {
    this.name = name;
  }

  public static FileShellCommand fromValue(String shellCommandAsString) {
    for (FileShellCommand fileShellCommand : FileShellCommand.values()) {
      if (fileShellCommand.name.equals(shellCommandAsString)) {
        return fileShellCommand;
      }
    }
    throw new IllegalArgumentException("Illegal value provided for enum constant: " + shellCommandAsString);
  }

}
