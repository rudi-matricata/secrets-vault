/**
 * Created on May 27, 2020 by Radoslav Filipov
 */
package com.secrets.vault.model;

import java.io.File;
import java.io.IOException;

/**
 * @author Filipov, Radoslav
 */
public interface FileEvent {

  void onEvent(File fileSubject) throws IOException;

}
