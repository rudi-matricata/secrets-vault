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
 * @author Filipov, Radoslav
 */
public class SecretsEncryptor extends CryptoProvider {

  public SecretsEncryptor() throws NoSuchAlgorithmException, NoSuchPaddingException {
    super();
  }

  public void init(String password) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    setSecretKey(password);
    this.cipher.init(Cipher.ENCRYPT_MODE, secretKey);
  }

  public String encrypt(byte[] plaintext) throws IllegalBlockSizeException, BadPaddingException {
    return Base64.getEncoder().encodeToString(cipher.doFinal(plaintext));
  }

}
