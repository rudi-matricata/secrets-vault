/**
 * Created on May 27, 2020 by Radoslav Filipov
 */
package com.secrets.vault.model;

import static com.secrets.vault.SecretsVaultUtils.getFileAbsolutePath;
import static com.secrets.vault.SecretsVaultUtils.readSensitiveValue;
import static java.lang.System.out;
import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Base64;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.secrets.vault.SecretsVaultUtils;
import com.secrets.vault.crypto.SecretsEncryptor;
import com.secrets.vault.exception.CryptoRuntimeException;
import com.secrets.vault.validation.MasterPasswordValidator;

/**
 * @author Filipov, Radoslav
 */
public class FileEncryptEvent implements FileEvent {

  private SecretsEncryptor secretsEncryptor;
  private MasterPasswordValidator masterPasswordValidator;

  public FileEncryptEvent() {
    try {
      this.secretsEncryptor = new SecretsEncryptor();
    } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
      throw new CryptoRuntimeException("Error while initializing cipher", e);
    }
    this.masterPasswordValidator = new MasterPasswordValidator();
  }

  /**
   * Should be called on file encryption request. First checks if the file exists.
   */
  @Override
  public void onEvent(String filename) throws IOException {
    File fileToBeEncrypted = new File(filename);
    String fileToBeEncryptedName = fileToBeEncrypted.getName();
    if (!fileToBeEncrypted.exists()) {
      throw new IllegalStateException("Requested file to be encrypted does NOT exist: " + fileToBeEncryptedName);
    }
    try {
      out.print("\tmaster password to secure the file: ");
      String masterPassword = readSensitiveValue();
      masterPasswordValidator.validate(masterPassword);
      secretsEncryptor.init(masterPassword);

      File encryptedFile = new File(getFileAbsolutePath(SecretsVaultUtils.ENCRYPED_FILENAME_PREFIX, fileToBeEncryptedName));
      encryptedFile.getParentFile().mkdirs();
      try (OutputStream os = new CipherOutputStream(new FileOutputStream(encryptedFile), secretsEncryptor.getCipher())) {
        try (InputStream fis = new FileInputStream(fileToBeEncrypted)) {
          byte[] buffer = new byte[8192];
          int count;
          while ((count = fis.read(buffer)) > 0) {
            os.write(buffer, 0, count);
          }
        }
      }

      FileSecret fileSecret = new FileSecret();
      fileSecret.setPasswordHashFromPlainPassword(masterPassword);
      fileSecret.setIv(getBase64EncodedIV());
      fileSecret.setUser(secretsEncryptor.encrypt(SecretsVaultUtils.CURRENT_USER.getBytes(UTF_8)));
      fileSecret.setEncryptedAt(new Date());
      SecretsVaultUtils.getObjectMapper().writeValue(new File(getFileAbsolutePath(SecretsVaultUtils.META_FILENAME_PREFIX, fileToBeEncryptedName)),
          fileSecret);

      out.println("\n\tFile successfully encrypted!");
    } catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidParameterSpecException | IllegalBlockSizeException
        | BadPaddingException e) {
      throw new CryptoRuntimeException("Error occured while trying to encrypt the provided secret", e);
    }
  }

  private String getBase64EncodedIV() throws InvalidParameterSpecException {
    return Base64.getEncoder().encodeToString(secretsEncryptor.getCipherIV());
  }
}
