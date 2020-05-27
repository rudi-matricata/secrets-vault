/**
 * Created on May 27, 2020 by Radoslav Filipov
 */
package com.secrets.vault.model;

import static com.secrets.vault.SecretsVaultUtils.CURRENT_USER;
import static com.secrets.vault.SecretsVaultUtils.OUTPUT_PATTERN;
import static java.lang.System.out;
import static java.text.MessageFormat.format;

import java.io.File;
import java.io.IOException;

import com.secrets.vault.SecretsVaultUtils;

/**
 * @author Filipov, Radoslav
 */
public class FileCreateEvent implements FileEvent {

  @Override
  public void onEvent(File fileSubject) throws IOException {
    if (fileSubject.exists()) {
      throw new IllegalStateException("Requested file already exists: " + fileSubject.getName());
    }
    out.print(format(OUTPUT_PATTERN, CURRENT_USER, "secret value"));
    String secret = SecretsVaultUtils.getScanner().next();
    SecretsVaultUtils.getObjectMapper().writeValue(fileSubject, new Secret(fileSubject.getName(), secret));
  }

}
