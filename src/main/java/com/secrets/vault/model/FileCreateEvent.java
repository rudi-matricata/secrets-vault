/**
 * Created on May 27, 2020 by Radoslav Filipov
 */
package com.secrets.vault.model;

import static java.lang.System.out;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Base64;
import java.util.Date;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.secrets.vault.SecretsVaultUtils;
import com.secrets.vault.crypto.SecretsEncryptor;
import com.secrets.vault.exception.CryptoRuntimeException;
import com.secrets.vault.validation.MasterPasswordValidator;
import com.secrets.vault.validation.NonBlankInputValidator;

/**
 * @author Filipov, Radoslav
 */
public class FileCreateEvent implements FileEvent {

  private SecretsEncryptor secretsEncryptor;
  private MasterPasswordValidator masterPasswordValidator;
  private NonBlankInputValidator nonBlankInputValidator;

  public FileCreateEvent() {
    try {
      this.secretsEncryptor = new SecretsEncryptor();
    } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
      throw new CryptoRuntimeException("Error while initializing cipher", e);
    }
    this.masterPasswordValidator = new MasterPasswordValidator();
    this.nonBlankInputValidator = new NonBlankInputValidator();
  }

  /**
   * Should be called on new file secret creation. First checks if the file exists (doesn't overwrite it).
   */
  @Override
  public void onEvent(File fileSubject) throws IOException {
    if (fileSubject.exists()) {
      throw new IllegalStateException("Requested file already exists: " + fileSubject.getName());
    }
    try {
      Scanner scanner = SecretsVaultUtils.getScanner();
      out.print("\tsecret value: ");
      String secret = scanner.next();
      nonBlankInputValidator.validate(secret);

      out.print("\tmaster password to secure the file: ");
      String masterPassword = scanner.next();
      masterPasswordValidator.validate(masterPassword);
      secretsEncryptor.init(masterPassword);

      FileSecret fileSecret = new FileSecret(secretsEncryptor.encrypt(secret.getBytes(StandardCharsets.UTF_8)));
      fileSecret.setPasswordHashFromPlainPassword(masterPassword);
      fileSecret.setIv(getBase64EncodedIV());
      fileSecret.setUser(SecretsVaultUtils.CURRENT_USER);
      fileSecret.setCreatedAt(new Date());
      SecretsVaultUtils.getObjectMapper().writeValue(fileSubject, fileSecret);

      out.println("\n\tFile successfully created!");
    } catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | IllegalBlockSizeException | BadPaddingException
        | InvalidParameterSpecException e) {
      throw new CryptoRuntimeException("Error occured while trying to encrypt the provided secret", e);
    }
  }

  private String getBase64EncodedIV() throws InvalidParameterSpecException {
    return Base64.getEncoder().encodeToString(secretsEncryptor.getCipherIV());
  }

}
