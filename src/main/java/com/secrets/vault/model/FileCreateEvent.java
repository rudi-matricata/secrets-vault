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
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

import com.secrets.vault.SecretsVaultUtils;
import com.secrets.vault.crypto.SecretsEncryptor;
import com.secrets.vault.exception.CryptoRuntimeException;

/**
 * @author Filipov, Radoslav
 */
public class FileCreateEvent implements FileEvent {

  private SecretsEncryptor secretsEncryptor;

  public FileCreateEvent() {
    try {
      this.secretsEncryptor = new SecretsEncryptor();
    } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
      throw new CryptoRuntimeException("Error while initializing cipher", e);
    }
  }

  /**
   * Should be called on new file secret creation. Checks if the file exists (doesn't overwrite it).
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

      out.print("\tmaster password to secure the file: ");
      String masterPassword = scanner.next();
      secretsEncryptor.init(masterPassword);

      FileSecret fileSecret = new FileSecret(fileSubject.getName(), secretsEncryptor.encrypt(secret.getBytes(StandardCharsets.UTF_8)));
      fileSecret.setIv(getBase64EncodedIV());
      fileSecret.setUser(SecretsVaultUtils.CURRENT_USER);
      SecretsVaultUtils.getObjectMapper().writeValue(fileSubject, fileSecret);

      out.println("File successfully created");
    } catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | IllegalBlockSizeException | BadPaddingException
        | InvalidParameterSpecException e) {
      throw new CryptoRuntimeException("Error occured while trying to encrypt the provided secret", e);
    }
  }

  private String getBase64EncodedIV() throws InvalidParameterSpecException {
    return Base64.getEncoder().encodeToString(secretsEncryptor.getCipher().getParameters().getParameterSpec(IvParameterSpec.class).getIV());
  }

}
