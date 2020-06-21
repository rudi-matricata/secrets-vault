/**
 * Created on Jun 21, 2020 by Radoslav Filipov
 */
package com.secrets.vault.event;

import static com.secrets.vault.SecretsVaultUtils.getFileAbsolutePath;
import static com.secrets.vault.SecretsVaultUtils.readSensitiveValue;
import static java.lang.System.out;

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
import com.secrets.vault.crypto.EncryptionManager;
import com.secrets.vault.exception.CryptoRuntimeException;
import com.secrets.vault.model.FileSecretMetadata;
import com.secrets.vault.validation.MasterPasswordValidator;

/**
 * @author Filipov, Radoslav
 */
public abstract class EncryptEvent implements FileEvent {

  protected EncryptionManager encryptionManager;
  protected MasterPasswordValidator masterPasswordValidator;

  public EncryptEvent() {
    try {
      this.encryptionManager = new EncryptionManager();
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
    encryptionManager.init(masterPassword);

    return masterPassword;
  }

  /**
   * Saves the metadata(user, used password hash etc.) related to the encrypted file.
   *
   * @param masterPassword
   *          The password use for protection(encryption) of the file
   * @param filename
   * @throws NoSuchAlgorithmException
   * @throws IllegalBlockSizeException
   * @throws BadPaddingException
   * @throws IOException
   * @throws InvalidParameterSpecException
   */
  protected void saveMetadata(String masterPassword, String filename) throws NoSuchAlgorithmException, IOException, InvalidParameterSpecException {
    FileSecretMetadata fileSecretMetadata = new FileSecretMetadata();
    fileSecretMetadata.setPasswordHashFromPlainPassword(masterPassword);
    fileSecretMetadata.setIv(getBase64EncodedIV());
    fileSecretMetadata.setEncryptedAt(new Date());

    SecretsVaultUtils.getObjectMapper().writeValue(new File(getFileAbsolutePath(SecretsVaultUtils.META_FILENAME_PREFIX, filename)),
        fileSecretMetadata);
  }

  private String getBase64EncodedIV() throws InvalidParameterSpecException {
    return Base64.getEncoder().encodeToString(encryptionManager.getCipherIV());
  }

  /**
   * Save the file using #CipherOutputStream and the provided #Cipher.
   *
   * @param fileToBeEncryptedName
   * @param dataWriter
   * @throws IOException
   */
  protected void encryptAndSaveFile(String fileToBeEncryptedName, DataWriter dataWriter) throws IOException {
    encryptionManager.setCurrentUserInAAD();

    File encryptedFile = new File(getFileAbsolutePath(SecretsVaultUtils.ENCRYPED_FILENAME_PREFIX, fileToBeEncryptedName));
    encryptedFile.getParentFile().mkdirs();
    try (OutputStream os = new CipherOutputStream(new FileOutputStream(encryptedFile), encryptionManager.getCipher())) {
      dataWriter.writeData(os);
    }
  }

  @FunctionalInterface
  interface DataWriter {

    void writeData(OutputStream os) throws IOException;
  }

}
