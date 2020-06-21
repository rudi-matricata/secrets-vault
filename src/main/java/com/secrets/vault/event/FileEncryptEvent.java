/**
 * Created on May 27, 2020 by Radoslav Filipov
 */
package com.secrets.vault.event;

import static java.lang.System.out;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import com.secrets.vault.exception.CryptoRuntimeException;

/**
 * @author Filipov, Radoslav
 */
public class FileEncryptEvent extends EncryptEvent {

  public FileEncryptEvent() {
    super();
  }

  /**
   * Should be called on file encryption request. First checks if the file exists.
   */
  @Override
  public synchronized void onEvent(String filename) throws IOException {
    File fileToBeEncrypted = new File(filename);
    String fileToBeEncryptedName = fileToBeEncrypted.getName();
    if (!fileToBeEncrypted.exists()) {
      throw new IllegalStateException("Requested file to be encrypted does NOT exist: " + fileToBeEncryptedName);
    }
    try {
      String masterPassword = readMasterPasswordAndInitEncryptor();

      encryptAndSaveFile(fileToBeEncryptedName, os -> {
        try (InputStream fis = new FileInputStream(fileToBeEncrypted)) {
          byte[] buffer = new byte[8192];
          int count;
          while ((count = fis.read(buffer)) > 0) {
            os.write(buffer, 0, count);
          }
        }
      });
      saveMetadata(masterPassword, fileToBeEncryptedName);

      out.println("\n\tFile successfully encrypted!");
    } catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidParameterSpecException | IllegalBlockSizeException
        | BadPaddingException e) {
      throw new CryptoRuntimeException("Error occured while trying to encrypt the provided secret", e);
    }
  }

}
