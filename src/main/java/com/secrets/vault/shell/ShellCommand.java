/**
 * Created on May 27, 2020 by Radoslav Filipov
 */
package com.secrets.vault.shell;

/**
 * @author Filipov, Radoslav
 */
public enum ShellCommand {

  READ("read"), CREATE("create"), EXIT("exit"), Q("q");

  private String name;

  private ShellCommand(String name) {
    this.name = name;
  }

  @Override
  public String toString() {
    return this.name;
  }

  public static ShellCommand fromValue(String shellCommandAsString) {
    for (ShellCommand shellCommand : ShellCommand.values()) {
      if (shellCommand.name.equals(shellCommandAsString)) {
        return shellCommand;
      }
    }
    throw new IllegalArgumentException("Illegal value provided for enum constant: " + shellCommandAsString);
  }

}
