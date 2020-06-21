/**
 * Created on May 27, 2020 by Radoslav Filipov
 */
package com.secrets.vault.event;

import static com.secrets.vault.SecretsVaultUtils.getObjectMapper;
import static com.secrets.vault.SecretsVaultUtils.readSensitiveValue;
import static java.lang.System.out;

import java.io.File;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import com.secrets.vault.exception.CryptoRuntimeException;
import com.secrets.vault.validation.NonBlankInputValidator;

/**
 * @author Filipov, Radoslav
 */
public class FileCreateEvent extends EncryptEvent {

  private NonBlankInputValidator nonBlankInputValidator;

  public FileCreateEvent() {
    super();
  }

  /**
   * Should be called on request for storing an encrypted secret. First checks if the file exists (doesn't overwrite
   * it).
   */
  @Override
  public synchronized void onEvent(String filename) throws IOException {
    File fileToBeCreated = new File(filename);
    String fileToBeCreatedName = fileToBeCreated.getName();
    if (fileToBeCreated.exists()) {
      throw new IllegalStateException("Requested file already exists: " + fileToBeCreatedName);
    }
    try {
      out.print("\tsecret value: ");
      String secret = readSensitiveValue();
      nonBlankInputValidator.validate(secret);

      String masterPassword = readMasterPasswordAndInitEncryptor();

      encryptAndSaveFile(fileToBeCreatedName, os -> getObjectMapper().writeValue(os, secret));
      saveMetadata(masterPassword, fileToBeCreatedName);

      out.println("\n\tFile successfully created!");
    } catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidParameterSpecException | IllegalBlockSizeException
        | BadPaddingException e) {
      throw new CryptoRuntimeException("Error occured while trying to encrypt the provided secret", e);
    }
  }

}
