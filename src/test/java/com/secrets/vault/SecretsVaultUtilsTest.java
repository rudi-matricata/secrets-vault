/**
 * Created on May 27, 2020 by Radoslav Filipov
 */
package com.secrets.vault;

import static com.secrets.vault.SecretsVaultUtils.getSHA256HashedValue;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import org.junit.jupiter.api.Test;

/**
 * @author Filipov, Radoslav
 */
public class SecretsVaultUtilsTest {

  @Test
  public void testSHA256Hashing() throws NoSuchAlgorithmException {
    assertArrayEquals(getSHA256HashedValue("same"), getSHA256HashedValue("same"),
        "Hashing the same value with the given algorithm should produce the same hash values");

    assertFalse(Arrays.equals(getSHA256HashedValue("one"), getSHA256HashedValue("another")),
        "Different values should result in different hash values");
  }

}
