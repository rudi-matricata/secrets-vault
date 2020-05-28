/**
 * Created on May 27, 2020 by Radoslav Filipov
 */
package com.secrets.vault.model;

import java.util.Date;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;

/**
 * @author Filipov, Radoslav
 */
@JsonInclude(Include.NON_EMPTY)
public class FileSecret {

  private static final String DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'";

  private String value;
  private String iv;
  private String user;

  @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = DATE_FORMAT, timezone = "UTC")
  private Date createdAt;

  public FileSecret() {
  }

  public FileSecret(String value) {
    this.value = value;
  }

  public String getValue() {
    return value;
  }

  public void setValue(String value) {
    this.value = value;
  }

  public String getIv() {
    return iv;
  }

  public void setIv(String iv) {
    this.iv = iv;
  }

  public String getUser() {
    return user;
  }

  public void setUser(String user) {
    this.user = user;
  }

  public Date getCreatedAt() {
    return createdAt;
  }

  public void setCreatedAt(Date createdAt) {
    this.createdAt = createdAt;
  }

}
