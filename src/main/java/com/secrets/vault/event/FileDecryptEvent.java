/**
 * Created on May 27, 2020 by Radoslav Filipov
 */
package com.secrets.vault.event;

import static com.secrets.vault.SecretsVaultUtils.ENCRYPED_FILENAME_PREFIX;
import static com.secrets.vault.SecretsVaultUtils.getFileAbsolutePath;
import static com.secrets.vault.SecretsVaultUtils.getObjectMapper;
import static java.lang.System.out;
import static java.util.Base64.getDecoder;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.secrets.vault.SecretsVaultUtils;
import com.secrets.vault.crypto.DecryptionManager;
import com.secrets.vault.exception.CryptoRuntimeException;
import com.secrets.vault.model.FileSecretMetadata;
import com.secrets.vault.validation.MasterPasswordValidator;

/**
 * @author Filipov, Radoslav
 */
public class FileDecryptEvent implements FileEvent {

  private DecryptionManager decryptionManager;
  private MasterPasswordValidator masterPasswordValidator;

  public FileDecryptEvent() {
    try {
      this.decryptionManager = new DecryptionManager();
    } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
      throw new CryptoRuntimeException("Error while initializing cipher", e);
    }
    this.masterPasswordValidator = new MasterPasswordValidator();
  }

  /**
   * Should be called on request for decrypting a file.
   */
  @Override
  public void onEvent(String filename) throws IOException {
    File fileToBeDecrypted = new File(getFileAbsolutePath(ENCRYPED_FILENAME_PREFIX, filename));
    File fileMetaInformation = new File(getFileAbsolutePath(SecretsVaultUtils.META_FILENAME_PREFIX, filename));
    if (!fileToBeDecrypted.exists() || !fileMetaInformation.exists()) {
      throw new IllegalStateException("Decryption cannot be performed because a file associated with it was not found");
    }

    try {
      out.print("\tmaster password used for file encryption: ");
      String password = SecretsVaultUtils.readSensitiveValue();
      masterPasswordValidator.validate(password);

      FileSecretMetadata secretMetadataRead = getObjectMapper().readValue(fileMetaInformation, FileSecretMetadata.class);
      masterPasswordValidator.validatePasswordMatchAgainstHashValue(password, secretMetadataRead);
      decryptionManager.init(password, getDecoder().decode(secretMetadataRead.getIv()));
      decryptionManager.setCurrentUserInAAD();

      try (CipherInputStream cis = new CipherInputStream(new FileInputStream(fileToBeDecrypted), decryptionManager.getCipher());
          OutputStream os = new FileOutputStream(fileToBeDecrypted.getName().replace(ENCRYPED_FILENAME_PREFIX, ""))) {
        byte[] buffer = new byte[8192];
        int count;
        while ((count = cis.read(buffer)) > 0) {
          os.write(buffer, 0, count);
        }
      }

      clearFields(secretMetadataRead);
      printJsonOutput(secretMetadataRead);
    } catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException e) {
      throw new CryptoRuntimeException("Error occured while trying to decrypt the secret", e);
    }
  }

  private void printJsonOutput(FileSecretMetadata fileSecretMetadata) throws JsonProcessingException {
    String jsonOutput = getObjectMapper().writerWithDefaultPrettyPrinter().writeValueAsString(fileSecretMetadata);
    jsonOutput = "\n\t" + jsonOutput.replace("\n", "\n\t");
    out.println(jsonOutput);
  }

  private void clearFields(FileSecretMetadata fileSecretMetadata) {
    fileSecretMetadata.setIv(null);
    fileSecretMetadata.setPasswordHash(null);
  }
}
