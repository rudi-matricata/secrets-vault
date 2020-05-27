/**
 * Created on May 27, 2020 by Radoslav Filipov
 */
package com.secrets.vault.model;

import static com.secrets.vault.SecretsVaultUtils.getObjectMapper;
import static java.lang.System.out;

import java.io.File;
import java.io.IOException;

/**
 * @author Filipov, Radoslav
 */
public class FileReadEvent implements FileEvent {

  @Override
  public void onEvent(File fileSubject) throws IOException {
    if (!fileSubject.exists()) {
      throw new IllegalStateException("Requested file for reading does NOT exist: " + fileSubject.getName());
    }
    Secret secretRead = getObjectMapper().readValue(fileSubject, Secret.class);
    out.print(getObjectMapper().writeValueAsString(secretRead));
  }

}
