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

  protected void setSecretKey(String password) throws NoSuchAlgorithmException, InvalidKeySpecException {
    int iterations = 1000;
    char[] chars = password.toCharArray();
    byte[] salt = getSalt();

    PBEKeySpec spec = new PBEKeySpec(chars, salt, iterations, 256);
    SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(KEY_DERIVATION_ALGORITHM);
    this.secretKey = new SecretKeySpec(keyFactory.generateSecret(spec).getEncoded(), "AES");
  }

  // change it not to be hardcoded
  private static byte[] getSalt() {
    return "abcdefghijklmnop".getBytes(StandardCharsets.UTF_8);
  }

  public Cipher getCipher() {
    return cipher;
  }

}
