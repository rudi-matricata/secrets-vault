/**
 * Created on May 27, 2020 by Radoslav Filipov
 */
package com.secrets.vault.model;

import static com.secrets.vault.SecretsVaultUtils.CURRENT_USER;
import static com.secrets.vault.SecretsVaultUtils.OUTPUT_PATTERN;
import static java.lang.System.out;
import static java.text.MessageFormat.format;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

import com.secrets.vault.SecretsVaultUtils;
import com.secrets.vault.crypto.SecretsEncryptor;
import com.secrets.vault.exception.CryptoRuntimeException;

/**
 * @author Filipov, Radoslav
 */
public class FileCreateEvent implements FileEvent {

  private SecretsEncryptor secretsEncryptor;

  public FileCreateEvent() {
    try {
      this.secretsEncryptor = new SecretsEncryptor();
    } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
      throw new CryptoRuntimeException("Error while initializing cipher", e);
    }
  }

  @Override
  public void onEvent(File fileSubject) throws IOException {
    if (fileSubject.exists()) {
      throw new IllegalStateException("Requested file already exists: " + fileSubject.getName());
    }
    try {
      out.print(format(OUTPUT_PATTERN, "password"));
      secretsEncryptor.init(SecretsVaultUtils.getScanner().next());

      out.print(format(OUTPUT_PATTERN, "secret value"));
      String secret = SecretsVaultUtils.getScanner().next();

      Secret secretObj = new Secret(fileSubject.getName(), secretsEncryptor.encrypt(secret.getBytes(StandardCharsets.UTF_8)));
      secretObj
          .setIv(Base64.getEncoder().encodeToString(secretsEncryptor.getCipher().getParameters().getParameterSpec(IvParameterSpec.class).getIV()));
      secretObj.setUser(SecretsVaultUtils.CURRENT_USER);
      SecretsVaultUtils.getObjectMapper().writeValue(fileSubject, secretObj);
    } catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | IllegalBlockSizeException | BadPaddingException
        | InvalidParameterSpecException e) {
      throw new CryptoRuntimeException("Fail", e);
    }

  }

}
