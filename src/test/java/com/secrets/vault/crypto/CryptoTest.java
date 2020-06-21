/**
 * Created on May 28, 2020 by Radoslav Filipov
 */
package com.secrets.vault.crypto;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.secrets.vault.exception.CryptoRuntimeException;

/**
 * Tests basic crypto functionality. Tests are NOT executed in parallel so no race condition problems will occur.
 *
 * @author Filipov, Radoslav
 */
public class CryptoTest {

  private static EncryptionManager secretsEncryptor;
  private static DecryptionManager secretsDecryptor;

  @BeforeAll
  private static void initialize() throws NoSuchAlgorithmException, NoSuchPaddingException {
    secretsEncryptor = new EncryptionManager();
    secretsDecryptor = new DecryptionManager();
  }

  @Test
  public void testKeyGenerationNegative() {
    assertThrows(IllegalArgumentException.class, () -> secretsEncryptor.init(null),
        "Trying to generate key with password vector of 'null' value should fail");

    assertThrows(IllegalArgumentException.class, () -> secretsDecryptor.init(null, new byte[0]),
        "Trying to generate key with password vector of 'null' value should fail");

    assertThrows(CryptoRuntimeException.class, () -> secretsDecryptor.init("testpass", new byte[0]),
        "Trying to generate key with illegal IV should fail");
  }

  @Test
  public void testKeyGenerationPositive()
      throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidParameterSpecException {
    secretsEncryptor.init("testpass");
    assertNotNull(secretsEncryptor.secretKey, "Secret key should not be null after initialization");
    assertEquals("AES", secretsEncryptor.secretKey.getAlgorithm(), "Expected 'AES' algorithm");

    secretsDecryptor.init("testpass", secretsEncryptor.getCipherIV());
  }

  @Test
  public void testFullEncryptionDecryptionScenarioPositive() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
      InvalidParameterSpecException, IllegalBlockSizeException, BadPaddingException {
    secretsEncryptor.init("testpass");
    secretsDecryptor.init("testpass", secretsEncryptor.getCipherIV());

    String plaintext = "secretvalue";
    byte[] ciphertext = secretsEncryptor.getCipher().doFinal(plaintext.getBytes(UTF_8));
    byte[] resultAfterDecryption = secretsDecryptor.getCipher().doFinal(ciphertext);

    assertArrayEquals(plaintext.getBytes(), resultAfterDecryption, "Plaintext and decrypted value should be the same");
  }

  @Test
  public void testFullEncryptionDecryptionScenarioNegative() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
      InvalidParameterSpecException, IllegalBlockSizeException, BadPaddingException {
    // 2 different passwords are used for key generation
    secretsEncryptor.init("testpass");
    secretsDecryptor.init("testpass-different", secretsEncryptor.getCipherIV());

    String plaintext = "secretvalue";
    byte[] ciphertext = secretsEncryptor.getCipher().doFinal(plaintext.getBytes(UTF_8));
    assertThrows(BadPaddingException.class, () -> secretsDecryptor.getCipher().doFinal(ciphertext),
        "Trying to decrypt with another key generated (for symmetric encryption) should fail");
  }

}
