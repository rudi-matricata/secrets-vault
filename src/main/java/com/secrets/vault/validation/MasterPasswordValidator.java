/**
 * Created on May 28, 2020 by Radoslav Filipov
 */
package com.secrets.vault.validation;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

import com.secrets.vault.SecretsVaultUtils;
import com.secrets.vault.exception.CryptoRuntimeException;
import com.secrets.vault.model.FileSecretMetadata;

/**
 * @author Filipov, Radoslav
 */
public class MasterPasswordValidator implements InputValidator {

  private static final String REGEX_FOR_DIGITS = ".*[0-9].*";
  private static final String REGEX_FOR_CAPITAL_LETTERS = ".*[A-Z].*";
  private static final String REGEX_FOR_SMALL_LETTERS = ".*[a-z].*";

  private NonBlankInputValidator nonBlankInputValidator = new NonBlankInputValidator();

  /**
   * Validates the password received that is used for AES key generation
   */
  @Override
  public void validate(String password) {
    nonBlankInputValidator.validate(password);

    if ((password.length() < 6) || (password.length() > 64)) {
      throw new IllegalArgumentException("Password should be at least 6 and no more than 64 characters long");
    }
    if (!containsSymbolsOfAllRequiredGroups(password)) {
      throw new IllegalArgumentException("Password should contain at least one of every group: digits, capital letters, small letters");
    }
  }

  private boolean containsSymbolsOfAllRequiredGroups(String tokenToValidate) {
    //@formatter:off
    return
        tokenToValidate.matches(REGEX_FOR_DIGITS) &&
        tokenToValidate.matches(REGEX_FOR_CAPITAL_LETTERS) &&
        tokenToValidate.matches(REGEX_FOR_SMALL_LETTERS);
    //@formatter:on

  }

  public void validatePasswordMatchAgainstHashValue(String password, FileSecretMetadata fileSecretMetadata) throws NoSuchAlgorithmException {
    byte[] providedPasswordHash = SecretsVaultUtils.getSHA256HashedValue(password);
    byte[] passwordHashFromFile = Base64.getDecoder().decode(fileSecretMetadata.getPasswordHash());
    if (!Arrays.equals(providedPasswordHash, passwordHashFromFile)) {
      throw new CryptoRuntimeException("Password used for encrpytion does NOT match the one provided for decryption");
    }
  }

}
