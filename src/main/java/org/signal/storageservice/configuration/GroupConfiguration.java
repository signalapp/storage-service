/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.configuration;

import org.signal.storageservice.util.ExactlySize;
import org.signal.storageservice.util.HexByteArrayAdapter;

import java.time.Duration;

import javax.validation.constraints.Positive;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

public record GroupConfiguration(
    @Positive int maxGroupSize,
    @Positive int maxGroupTitleLengthBytes,
    @Positive int maxGroupDescriptionLengthBytes,
    @JsonDeserialize(using = HexByteArrayAdapter.Deserializing.class) @ExactlySize(32) byte[] externalServiceSecret,
    Duration groupSendCredentialExpirationTime,
    Duration groupSendCredentialMinimumLifetime) {

  public static final Duration DEFAULT_GROUP_SEND_CREDENTIAL_EXPIRATION_INTERVAL = Duration.ofDays(1);
  public static final Duration DEFAULT_GROUP_SEND_CREDENTIAL_MINIMUM_LIFETIME = Duration.ofHours(2);

  public GroupConfiguration {
    if (groupSendCredentialExpirationTime == null) {
      groupSendCredentialExpirationTime = DEFAULT_GROUP_SEND_CREDENTIAL_EXPIRATION_INTERVAL;
    }
    if (groupSendCredentialMinimumLifetime == null) {
      groupSendCredentialMinimumLifetime = DEFAULT_GROUP_SEND_CREDENTIAL_MINIMUM_LIFETIME;
    }
  }

}
