/**
 * Created on Jun 21, 2020 by Radoslav Filipov
 */
package com.secrets.vault.event;

import static com.secrets.vault.SecretsVaultUtils.getFileAbsolutePath;
import static com.secrets.vault.SecretsVaultUtils.readSensitiveValue;
import static java.lang.System.out;
import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
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
import com.secrets.vault.model.FileSecretMetadata;
import com.secrets.vault.validation.MasterPasswordValidator;

/**
 * @author Filipov, Radoslav
 */
public abstract class EncryptEvent implements FileEvent {

  protected SecretsEncryptor secretsEncryptor;
  protected MasterPasswordValidator masterPasswordValidator;

  public EncryptEvent() {
    try {
      this.secretsEncryptor = new SecretsEncryptor();
    } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
      throw new CryptoRuntimeException("Error while initializing cipher", e);
    }
    this.masterPasswordValidator = new MasterPasswordValidator();
  }

  /**
   * @return The master password used for encryption
   * @throws InvalidKeyException
   * @throws NoSuchAlgorithmException
   * @throws InvalidKeySpecException
   */
  protected String readMasterPasswordAndInitEncryptor() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
    out.print("\tmaster password to secure the file: ");
    String masterPassword = readSensitiveValue();
    masterPasswordValidator.validate(masterPassword);
    secretsEncryptor.init(masterPassword);

    return masterPassword;
  }

  protected void saveMetadata(String masterPassword, String filename)
      throws NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidParameterSpecException {
    FileSecretMetadata fileSecretMetadata = new FileSecretMetadata();
    fileSecretMetadata.setPasswordHashFromPlainPassword(masterPassword);
    fileSecretMetadata.setIv(getBase64EncodedIV());
    fileSecretMetadata.setUser(secretsEncryptor.encrypt(SecretsVaultUtils.CURRENT_USER.getBytes(UTF_8)));
    fileSecretMetadata.setEncryptedAt(new Date());

    SecretsVaultUtils.getObjectMapper().writeValue(new File(getFileAbsolutePath(SecretsVaultUtils.META_FILENAME_PREFIX, filename)),
        fileSecretMetadata);
  }

  private String getBase64EncodedIV() throws InvalidParameterSpecException {
    return Base64.getEncoder().encodeToString(secretsEncryptor.getCipherIV());
  }

  protected void encryptAndSaveFile(String fileToBeEncryptedName, DataWriter dataWriter) throws IOException {
    File encryptedFile = new File(getFileAbsolutePath(SecretsVaultUtils.ENCRYPED_FILENAME_PREFIX, fileToBeEncryptedName));
    encryptedFile.getParentFile().mkdirs();
    try (OutputStream os = new CipherOutputStream(new FileOutputStream(encryptedFile), secretsEncryptor.getCipher())) {
      dataWriter.writeData(os);
    }
  }

  @FunctionalInterface
  interface DataWriter {

    void writeData(OutputStream os) throws IOException;
  }

}
