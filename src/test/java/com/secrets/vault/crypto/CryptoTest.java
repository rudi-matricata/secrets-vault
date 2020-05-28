/**
 * Created on May 28, 2020 by Radoslav Filipov
 */
package com.secrets.vault.crypto;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Base64;

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

  private static SecretsEncryptor secretsEncryptor;
  private static SecretsDecryptor secretsDecryptor;

  @BeforeAll
  private static void initialize() throws NoSuchAlgorithmException, NoSuchPaddingException {
    secretsEncryptor = new SecretsEncryptor();
    secretsDecryptor = new SecretsDecryptor();
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
    String base64EncodedCiphertext = secretsEncryptor.encrypt(plaintext.getBytes(UTF_8));
    String resultAfterDecryption = secretsDecryptor.decrypt(Base64.getDecoder().decode(base64EncodedCiphertext));

    assertEquals(plaintext, resultAfterDecryption, "Plaintext and decrypted value shoudl be the same");
  }

  @Test
  public void testFullEncryptionDecryptionScenarioNegative() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException,
      InvalidParameterSpecException, IllegalBlockSizeException, BadPaddingException {
    // 2 different passwords are used for key generation
    secretsEncryptor.init("testpass");
    secretsDecryptor.init("testpass-different", secretsEncryptor.getCipherIV());

    String plaintext = "secretvalue";
    String base64EncodedCiphertext = secretsEncryptor.encrypt(plaintext.getBytes(UTF_8));
    assertThrows(BadPaddingException.class, () -> secretsDecryptor.decrypt(Base64.getDecoder().decode(base64EncodedCiphertext)),
        "Trying to decrypt with another key generated (for symmetric encryption) should fail");
  }

}
