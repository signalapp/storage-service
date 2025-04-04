/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.configuration;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import jakarta.validation.constraints.NotEmpty;

public class AuthenticationConfiguration {

  @JsonProperty
  @NotEmpty
  private String key;

  public byte[] getKey() throws DecoderException {
    return Hex.decodeHex(key);
  }

}
