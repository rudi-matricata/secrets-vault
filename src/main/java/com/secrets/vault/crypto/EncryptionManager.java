/**
 * Created on May 27, 2020 by Radoslav Filipov
 */
package com.secrets.vault.crypto;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

/**
 * Class used for AES encryption. Currently GCM mode with NoPadding is used.
 *
 * @author Filipov, Radoslav
 */
public class EncryptionManager extends CryptoProvider {

  public EncryptionManager() throws NoSuchAlgorithmException, NoSuchPaddingException {
    super();
  }

  /**
   * Initializes the cipher in encryption mode and with key derived from the provided password using
   * PBKDF2WithHmacSHA256 algorithm.
   *
   * @param password
   * @throws NoSuchAlgorithmException
   * @throws InvalidKeySpecException
   * @throws InvalidKeyException
   */
  public void init(String password) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    setSecretKey(password);
    this.cipher.init(Cipher.ENCRYPT_MODE, secretKey);
  }

}
