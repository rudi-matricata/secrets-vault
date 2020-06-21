/**
 * Created on May 27, 2020 by Radoslav Filipov
 */
package com.secrets.vault.crypto;

import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Base class that holds #Cipher and #Key objects for AES crypto operations
 *
 * @author Filipov, Radoslav
 */
public abstract class CryptoProvider {

  protected Cipher cipher;
  protected Key secretKey;

  private static final String KEY_DERIVATION_ALGORITHM = "PBKDF2WithHmacSHA256";
  private static final String CRYPTO_ALGORITHM = "AES/CBC/PKCS5Padding";
  private static final int NUMBER_OF_ITERATIONS = 1000;
  private static final int KEY_LENGTH = 256;

  public CryptoProvider() throws NoSuchAlgorithmException, NoSuchPaddingException {
    this.cipher = Cipher.getInstance(CRYPTO_ALGORITHM);
  }

  /**
   * Derives an AES key.
   *
   * @param password
   *          Password secret used for AES key derivation.
   * @throws NoSuchAlgorithmException
   * @throws InvalidKeySpecException
   */
  protected void setSecretKey(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
    if (password == null) {
      throw new IllegalArgumentException("Password used for key generation should not be null");
    }
    PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), getSalt(), NUMBER_OF_ITERATIONS, KEY_LENGTH);
    SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(KEY_DERIVATION_ALGORITHM);

    this.secretKey = new SecretKeySpec(keyFactory.generateSecret(keySpec).getEncoded(), "AES");
  }

  /**
   * Generates salt used in key generation. Currently it is a hardcoded one.
   *
   * @return salt value
   */
  private static byte[] getSalt() {
    return "abcdefghijklmnop".getBytes(StandardCharsets.UTF_8);
  }

  public byte[] getCipherIV() throws InvalidParameterSpecException {
    return cipher.getParameters().getParameterSpec(IvParameterSpec.class).getIV();
  }

  public Cipher getCipher() {
    return this.cipher;
  }

}
