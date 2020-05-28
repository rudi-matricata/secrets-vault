/**
 * Created on May 27, 2020 by Radoslav Filipov
 */
package com.secrets.vault.exception;

/**
 * @author Filipov, Radoslav
 */
public class CryptoRuntimeException extends RuntimeException {

  public CryptoRuntimeException(String message, Throwable throwable) {
    super(message, throwable);
  }

}
