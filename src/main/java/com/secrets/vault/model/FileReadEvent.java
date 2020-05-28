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

import com.fasterxml.jackson.core.JsonProcessingException;
import com.secrets.vault.SecretsVaultUtils;
import com.secrets.vault.crypto.SecretsDecryptor;
import com.secrets.vault.exception.CryptoRuntimeException;
import com.secrets.vault.exception.IllegalFileAccessException;
import com.secrets.vault.validation.MasterPasswordValidator;

/**
 * @author Filipov, Radoslav
 */
public class FileReadEvent implements FileEvent {

  private SecretsDecryptor secretsDecryptor;
  private MasterPasswordValidator masterPasswordValidator;

  public FileReadEvent() {
    try {
      this.secretsDecryptor = new SecretsDecryptor();
    } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
      throw new CryptoRuntimeException("Error while initializing cipher", e);
    }
    this.masterPasswordValidator = new MasterPasswordValidator();
  }

  /**
   * Should be called on request for reading a file.
   */
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
      String password = SecretsVaultUtils.getScanner().next();
      masterPasswordValidator.validate(password);
      masterPasswordValidator.validatePasswordMatchAgainstHashValue(password, secretRead);

      secretsDecryptor.init(password, getDecoder().decode(secretRead.getIv()));

      secretRead.setValue(secretsDecryptor.decrypt(getDecoder().decode(secretRead.getValue())));
      clearFields(secretRead);
    } catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new CryptoRuntimeException("Error occured while trying to decrypt the secret", e);
    }
    printJsonOutput(secretRead);
  }

  private void printJsonOutput(FileSecret fileSecret) throws JsonProcessingException {
    String jsonOutput = getObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(fileSecret);
    jsonOutput = "\n\t" + jsonOutput.replace("\n", "\n\t");
    out.println(jsonOutput);
  }

  private void clearFields(FileSecret fileSecret) {
    fileSecret.setIv(null);
    fileSecret.setUser(null);
    fileSecret.setPasswordHash(null);
  }
}
