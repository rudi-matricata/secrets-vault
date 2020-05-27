/**
 * Created on May 27, 2020 by Radoslav Filipov
 */
package com.secrets.vault.model;

import com.fasterxml.jackson.annotation.JsonIgnore;

/**
 * @author Filipov, Radoslav
 */
public class Secret {

  @JsonIgnore
  private String name;
  private String value;

  public Secret() {
  }

  public Secret(String name, String value) {
    this.name = name;
    this.value = value;
  }

  public String getName() {
    return name;
  }

  public void setName(String name) {
    this.name = name;
  }

  public String getValue() {
    return value;
  }

  public void setValue(String value) {
    this.value = value;
  }

}
