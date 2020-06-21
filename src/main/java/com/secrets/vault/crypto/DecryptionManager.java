/**
 * Created on May 27, 2020 by Radoslav Filipov
 */
package com.secrets.vault.crypto;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;

import com.secrets.vault.exception.CryptoRuntimeException;

/**
 * Class used for AES decryption. Currently GCM mode with NoPadding is used.
 *
 * @author Filipov, Radoslav
 */
public class DecryptionManager extends CryptoProvider {

  private static final int GCM_IV_LENGTH = 128;

  public DecryptionManager() throws NoSuchAlgorithmException, NoSuchPaddingException {
    super();
  }

  /**
   * Initializes the cipher in decryption mode, with key derived from the provided password using
   * PBKDF2WithHmacSHA256 algorithm and the given IV.
   *
   * @param password
   * @param iv
   * @throws NoSuchAlgorithmException
   * @throws InvalidKeySpecException
   * @throws InvalidKeyException
   */
  public void init(String password, byte[] iv) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    setSecretKey(password);
    try {
      this.cipher.init(Cipher.DECRYPT_MODE, secretKey, new GCMParameterSpec(GCM_IV_LENGTH, iv));
    } catch (InvalidAlgorithmParameterException e) {
      throw new CryptoRuntimeException("Invalid IV parameter provided", e);
    }
  }

}
