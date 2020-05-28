/**
 * Created on May 27, 2020 by Radoslav Filipov
 */
package com.secrets.vault.model;

import static com.secrets.vault.SecretsVaultUtils.CURRENT_USER;
import static com.secrets.vault.SecretsVaultUtils.OUTPUT_PATTERN;
import static com.secrets.vault.SecretsVaultUtils.getObjectMapper;
import static java.lang.System.out;
import static java.text.MessageFormat.format;

import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.secrets.vault.SecretsVaultUtils;
import com.secrets.vault.crypto.SecretsDecryptor;
import com.secrets.vault.exception.CryptoRuntimeException;

/**
 * @author Filipov, Radoslav
 */
public class FileReadEvent implements FileEvent {

  private SecretsDecryptor secretsDecryptor;

  public FileReadEvent() {
    try {
      this.secretsDecryptor = new SecretsDecryptor();
    } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
      throw new CryptoRuntimeException("Error while initializing cipher", e);
    }
  }

  @Override
  public void onEvent(File fileSubject) throws IOException {
    if (!fileSubject.exists()) {
      throw new IllegalStateException("Requested file for reading does NOT exist: " + fileSubject.getName());
    }

    Secret secretRead = getObjectMapper().readValue(fileSubject, Secret.class);
    try {
      out.print(format(OUTPUT_PATTERN, CURRENT_USER, "password"));
      secretsDecryptor.init(SecretsVaultUtils.getScanner().next(), Base64.getDecoder().decode(secretRead.getIv()));

      secretRead.setValue(secretsDecryptor.decrypt(Base64.getDecoder().decode(secretRead.getValue())));
    } catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new CryptoRuntimeException("Fail", e);
    }

    out.print(getObjectMapper().writeValueAsString(secretRead));
  }

}
