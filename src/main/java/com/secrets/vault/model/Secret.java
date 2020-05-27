/**
 * Created on May 27, 2020 by Radoslav Filipov
 */
package com.secrets.vault.model;

/**
 * @author Filipov, Radoslav
 */
public class Secret {

  private String name;
  private String value;

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
