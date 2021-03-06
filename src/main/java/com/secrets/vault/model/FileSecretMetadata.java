/**
 * Created on May 27, 2020 by Radoslav Filipov
 */
package com.secrets.vault.model;

import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Date;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.secrets.vault.SecretsVaultUtils;

/**
 * @author Filipov, Radoslav
 */
@JsonInclude(Include.NON_EMPTY)
public class FileSecretMetadata {

  private static final String DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";

  private String iv;
  private String passwordHash;

  private byte[] encrypedMetadata;

  @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = DATE_FORMAT, timezone = "UTC")
  private Date encryptedAt;

  public String getIv() {
    return iv;
  }

  public void setIv(String iv) {
    this.iv = iv;
  }

  public Date getEncryptedAt() {
    return encryptedAt;
  }

  public void setEncryptedAt(Date createdAt) {
    this.encryptedAt = createdAt;
  }

  public String getPasswordHash() {
    return passwordHash;
  }

  /**
   * Hashes the given password using SHA-256
   *
   * @param password
   *          Plain password as string
   * @throws NoSuchAlgorithmException
   */
  public void setPasswordHashFromPlainPassword(String password) throws NoSuchAlgorithmException {
    this.passwordHash = Base64.getEncoder().encodeToString(SecretsVaultUtils.getSHA256HashedValue(password));
  }

  /**
   * Used by Jackson for deserialization
   *
   * @param passwordHash
   */
  public void setPasswordHash(String passwordHash) {
    this.passwordHash = passwordHash;
  }

  public byte[] getEncrypedMetadata() {
    return encrypedMetadata;
  }

  public void setEncrypedMetadata(byte[] encrypedMetadata) {
    this.encrypedMetadata = encrypedMetadata;
  }

}
