/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.configuration;

import org.signal.storageservice.util.ExactlySize;
import org.signal.storageservice.util.HexByteArrayAdapter;

import java.time.Duration;

import jakarta.validation.constraints.Positive;

import com.fasterxml.jackson.databind.annotation.JsonDeserialize;

public record GroupConfiguration(
    @Positive int maxGroupSize,
    @Positive int maxGroupTitleLengthBytes,
    @Positive int maxGroupDescriptionLengthBytes,
    @JsonDeserialize(using = HexByteArrayAdapter.Deserializing.class) @ExactlySize(32) byte[] externalServiceSecret,
    Duration groupSendEndorsementExpirationTime,
    Duration groupSendEndorsementMinimumLifetime) {

  public static final Duration DEFAULT_GROUP_SEND_ENDORSEMENT_EXPIRATION_INTERVAL = Duration.ofDays(1);
  public static final Duration DEFAULT_GROUP_SEND_ENDORSEMENT_MINIMUM_LIFETIME = Duration.ofHours(6);

  public GroupConfiguration {
    if (groupSendEndorsementExpirationTime == null) {
      groupSendEndorsementExpirationTime = DEFAULT_GROUP_SEND_ENDORSEMENT_EXPIRATION_INTERVAL;
    }
    if (groupSendEndorsementMinimumLifetime == null) {
      groupSendEndorsementMinimumLifetime = DEFAULT_GROUP_SEND_ENDORSEMENT_MINIMUM_LIFETIME;
    }
  }

}
