/**
 * Created on May 27, 2020 by Radoslav Filipov
 */
package com.secrets.vault.validation;

/**
 * @author Filipov, Radoslav
 */
public class NonBlankInputValidator implements InputValidator {

  /**
   * Validates that the given input is not blank (null, empty, etc.)
   */
  @Override
  public void validate(String tokenToValidate) {
    if ((tokenToValidate == null) || tokenToValidate.isBlank()) {
      throw new IllegalArgumentException("Provided value should not be blank");
    }
  }

}
