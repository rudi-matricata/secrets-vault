/**
 * Created on May 27, 2020 by Radoslav Filipov
 */
package com.secrets.vault.model;

import static com.secrets.vault.SecretsVaultUtils.getObjectMapper;
import static java.lang.System.out;
import static java.util.Base64.getDecoder;

import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.secrets.vault.SecretsVaultUtils;
import com.secrets.vault.crypto.SecretsDecryptor;
import com.secrets.vault.exception.CryptoRuntimeException;
import com.secrets.vault.exception.IllegalFileAccessException;

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

    FileSecret secretRead = getObjectMapper().readValue(fileSubject, FileSecret.class);
    if (!SecretsVaultUtils.CURRENT_USER.equals(secretRead.getUser())) {
      throw new IllegalFileAccessException("Illegal access to file. The file requested to be read belongs to: " + secretRead.getUser());
    }
    try {
      out.print("\tmaster password used for file encryption: ");
      secretsDecryptor.init(SecretsVaultUtils.getScanner().next(), getDecoder().decode(secretRead.getIv()));

      secretRead.setValue(secretsDecryptor.decrypt(getDecoder().decode(secretRead.getValue())));
      secretRead.setIv(null);
      secretRead.setUser(null);
    } catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new CryptoRuntimeException("Error occured while trying to decrypt the secret", e);
    }

    out.print(getObjectMapper().writeValueAsString(secretRead) + "\n");
  }

}
