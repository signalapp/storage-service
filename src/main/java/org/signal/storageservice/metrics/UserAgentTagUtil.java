/*
 * Copyright 2013-2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.metrics;

import io.micrometer.core.instrument.Tag;
import org.signal.storageservice.util.ua.UnrecognizedUserAgentException;
import org.signal.storageservice.util.ua.UserAgentUtil;

/**
 * Utility class for extracting platform/version metrics tags from User-Agent strings.
 */
public class UserAgentTagUtil {

  public static final String PLATFORM_TAG = "platform";

  private UserAgentTagUtil() {
  }

  public static Tag getPlatformTag(final String userAgentString) {
    String platform;

    try {
      platform = UserAgentUtil.getPlatformFromUserAgentString(userAgentString).name().toLowerCase();
    } catch (final UnrecognizedUserAgentException e) {
      platform = "unrecognized";
    }

    return Tag.of(PLATFORM_TAG, platform);
  }
}
