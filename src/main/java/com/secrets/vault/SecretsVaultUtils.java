/**
 * Created on May 27, 2020 by Radoslav Filipov
 */
package com.secrets.vault;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * @author Filipov, Radoslav
 */
public final class SecretsVaultUtils {

  private SecretsVaultUtils() {
    // this class should not be instantiated
  }

  public static final String CURRENT_USER = System.getProperty("user.name");
  public static final String OUTPUT_PATTERN = "[" + CURRENT_USER + "] {0}: ";

  private static ObjectMapper objectMapper;
  private static Scanner scanner;

  public static ObjectMapper getObjectMapper() {
    if (objectMapper == null) {
      return new ObjectMapper();
    }
    return objectMapper;
  }

  public static Scanner getScanner() {
    if (scanner == null) {
      return new Scanner(System.in);
    }
    return scanner;
  }

  public static byte[] getSHA256HashedValue(String tokenToBeHashed) throws NoSuchAlgorithmException {
    MessageDigest sha256MessageDigest = MessageDigest.getInstance("SHA-256");
    return sha256MessageDigest.digest(tokenToBeHashed.getBytes(StandardCharsets.UTF_8));
  }

}
