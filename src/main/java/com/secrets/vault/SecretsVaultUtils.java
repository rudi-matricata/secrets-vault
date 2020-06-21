/**
 * Created on May 27, 2020 by Radoslav Filipov
 */
package com.secrets.vault;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.MessageFormat;
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

  public static final String ENCRYPED_FILENAME_PREFIX = "encrypted_";
  public static final String META_FILENAME_PREFIX = "meta_";

  private static ObjectMapper objectMapper;
  private static Scanner scanner;

  public static ObjectMapper getObjectMapper() {
    if (objectMapper == null) {
      return new ObjectMapper();
    }
    return objectMapper;
  }

  /**
   * @return a Scanner object attached to the System.in input stream
   */
  public static Scanner getScanner() {
    if (scanner == null) {
      return new Scanner(System.in);
    }
    return scanner;
  }

  /**
   * Hashes a given token using 'SHA-256' algorithm.
   *
   * @param tokenToBeHashed
   * @return Hashed token value
   * @throws NoSuchAlgorithmException
   */
  public static byte[] getSHA256HashedValue(String tokenToBeHashed) throws NoSuchAlgorithmException {
    MessageDigest sha256MessageDigest = MessageDigest.getInstance("SHA-256");
    return sha256MessageDigest.digest(tokenToBeHashed.getBytes(StandardCharsets.UTF_8));
  }

  /**
   * Reads and return the secret value from console, without showing it.
   */
  public static String readSensitiveValue() {
    String sensitiveValue = String.valueOf(System.console().readPassword());
    System.out.print(MessageFormat.format("\t{0}({1} chars)\n", "*".repeat(sensitiveValue.length()), sensitiveValue.length()));
    return sensitiveValue;
  }

  public static String getFileAbsolutePath(String filenamePrefix, String filename) {
    return System.getProperty("user.home") + "\\secrets_keeper\\" + filenamePrefix + filename;
  }

}
