/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.configuration;

import com.fasterxml.jackson.annotation.JsonProperty;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

import javax.validation.constraints.NotEmpty;
import javax.validation.constraints.Positive;

public class GroupConfiguration {
  @JsonProperty
  @Positive
  private int maxGroupSize;

  @JsonProperty
  @NotEmpty
  private String externalServiceSecret;

  public int getMaxGroupSize() {
    return maxGroupSize;
  }

  public byte[] getExternalServiceSecret() throws DecoderException {
    return Hex.decodeHex(externalServiceSecret);
  }
}
