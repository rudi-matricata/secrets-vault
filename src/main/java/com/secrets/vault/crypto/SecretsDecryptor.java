/**
 * Created on May 27, 2020 by Radoslav Filipov
 */
package com.secrets.vault.crypto;

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

import com.secrets.vault.exception.CryptoRuntimeException;

/**
 * Class used for AES decryption. Currently CBC mode with PKCS5Padding is used.
 *
 * @author Filipov, Radoslav
 */
public class SecretsDecryptor extends CryptoProvider {

  public SecretsDecryptor() throws NoSuchAlgorithmException, NoSuchPaddingException {
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
      this.cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
    } catch (InvalidAlgorithmParameterException e) {
      throw new CryptoRuntimeException("Invalid IV parameter provided", e);
    }
  }

  /**
   * Performs decryption.
   *
   * @param ciphertext
   *          Ciphertext to be decrypted.
   * @return Base64 encoded plaintext that corresponds to the given ciphertext.
   * @throws IllegalBlockSizeException
   * @throws BadPaddingException
   */
  public String decrypt(byte[] ciphertext) throws IllegalBlockSizeException, BadPaddingException {
    return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
  }

}
