/**
 * Created on May 28, 2020 by Radoslav Filipov
 */
package com.secrets.vault.validation;

import static org.junit.jupiter.api.Assertions.assertThrows;

import org.junit.jupiter.api.Test;

/**
 * @author Filipov, Radoslav
 */
public class InputValidatorsTest {

  private NonBlankInputValidator nonBlankInputValidator = new NonBlankInputValidator();
  private MasterPasswordValidator masterPasswordValidator = new MasterPasswordValidator();

  @Test
  public void testNonBlankInputValidatorIllegalTokens() {
    testIllegalTokens(nonBlankInputValidator);
  }

  @Test
  public void testNonBlankInputValidatorLegalTokens() {
    nonBlankInputValidator.validate("null");
    nonBlankInputValidator.validate("   1");
    nonBlankInputValidator.validate("     _");
    nonBlankInputValidator.validate("abcdefghijklmnopqrstuvwxyz");
  }

  @Test
  public void testMasterPasswordValidatorIllegalTokens() {
    testIllegalTokens(masterPasswordValidator);
    assertThrows(IllegalArgumentException.class, () -> masterPasswordValidator.validate("Null1"), "Password with length less than 6 is illegal");
    assertThrows(IllegalArgumentException.class, () -> masterPasswordValidator.validate("Nul1".repeat(16) + "1"),
        "Password with length more than 64 is illegal");
    assertThrows(IllegalArgumentException.class, () -> masterPasswordValidator.validate("null12"),
        "Password should contain at least 1 capital letter");
    assertThrows(IllegalArgumentException.class, () -> masterPasswordValidator.validate("NULL12"), "Password should contain at least 1 small letter");
    assertThrows(IllegalArgumentException.class, () -> masterPasswordValidator.validate("NuLlLl"), "Password should contain at least 1 digit");
  }

  @Test
  public void testMasterPasswordValidatorLegalTokens() {
    masterPasswordValidator.validate("Sixsi6");
    masterPasswordValidator.validate("Nul1".repeat(16));
    masterPasswordValidator.validate("VeryRaNdOM1Pa33W0rD");
  }

  private void testIllegalTokens(InputValidator inputValidator) {
    assertThrows(IllegalArgumentException.class, () -> inputValidator.validate(null), "Token with null value is illegal");
    assertThrows(IllegalArgumentException.class, () -> inputValidator.validate(""), "Token with empty string value is illegal");
    assertThrows(IllegalArgumentException.class, () -> inputValidator.validate("      "), "Token which contains only whitespaces is illegal");
  }

}
