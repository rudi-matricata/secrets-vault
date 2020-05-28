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
 * @author Filipov, Radoslav
 */
public class SecretsDecryptor extends CryptoProvider {

  public SecretsDecryptor() throws NoSuchAlgorithmException, NoSuchPaddingException {
    super();
  }

  public void init(String password, byte[] iv) throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
    setSecretKey(password);
    try {
      this.cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(iv));
    } catch (InvalidAlgorithmParameterException e) {
      throw new CryptoRuntimeException("Fail", e);
    }
  }

  public String decrypt(byte[] ciphertext) throws IllegalBlockSizeException, BadPaddingException {
    return new String(cipher.doFinal(ciphertext), StandardCharsets.UTF_8);
  }

}
