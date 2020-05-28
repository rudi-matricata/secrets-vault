/**
 * Created on May 27, 2020 by Radoslav Filipov
 */
package com.secrets.vault.crypto;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * Class used for AES encryption. Currently CBC mode with PKCS5Padding is used.
 *
 * @author Filipov, Radoslav
 */
public class SecretsEncryptor extends CryptoProvider {

  public SecretsEncryptor() throws NoSuchAlgorithmException, NoSuchPaddingException {
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

  /**
   * Performs encryption.
   *
   * @param plaintext
   *          Plaintext to be encrypted.
   * @return
   *         Cipher text as base64 encoded string.
   * @throws IllegalBlockSizeException
   * @throws BadPaddingException
   */
  public String encrypt(byte[] plaintext) throws IllegalBlockSizeException, BadPaddingException {
    return Base64.getEncoder().encodeToString(cipher.doFinal(plaintext));
  }

}
