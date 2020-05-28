/**
 * Created on May 27, 2020 by Radoslav Filipov
 */
package com.secrets.vault.crypto;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Base class that holds #Cipher and #Key
 *
 * @author Filipov, Radoslav
 */
public abstract class CryptoProvider {

  protected Cipher cipher;
  protected Key secretKey;

  private static final String KEY_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA256";
  private static final String CRYPTO_ALGORITHM = "AES/CBC/PKCS5Padding";

  public CryptoProvider() throws NoSuchAlgorithmException, NoSuchPaddingException {
    this.cipher = Cipher.getInstance(CRYPTO_ALGORITHM);
  }

  /**
   * Derives an AES key and sets it.
   *
   * @param password
   *          Password secret used for AES key derivation.
   * @throws NoSuchAlgorithmException
   * @throws InvalidKeySpecException
   */
  protected void setSecretKey(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
    final int iterations = 1000;
    final int keyLength = 256;
    char[] chars = password.toCharArray();
    byte[] salt = getSalt();

    PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, keyLength);
    SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(KEY_DERIVATION_ALGORITHM);

    this.secretKey = new SecretKeySpec(keyFactory.generateSecret(spec).getEncoded(), "AES");
  }

  /**
   * Generates salt used in key generation. Currently it is a hardcoded one.
   *
   * @return salt value
   */
  private static byte[] getSalt() {
    return "abcdefghijklmnop".getBytes(StandardCharsets.UTF_8);
  }

  public Cipher getCipher() {
    return cipher;
  }

}
