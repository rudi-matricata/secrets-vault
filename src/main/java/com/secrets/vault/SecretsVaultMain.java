/**
 * Created on May 27, 2020 by Radoslav Filipov
 */
package com.secrets.vault;

import java.io.IOException;

import com.secrets.vault.shell.ShellProcessor;

/**
 * @author Filipov, Radoslav
 */
public class SecretsVaultMain {

  public static void main(String[] args) throws IOException {
    ShellProcessor.process();
  }

}
