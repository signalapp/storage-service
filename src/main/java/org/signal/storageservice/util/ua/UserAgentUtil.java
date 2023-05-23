/*
 * Copyright 2013-2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.util.ua;

import java.util.EnumMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class UserAgentUtil {

    private static final Pattern STANDARD_UA_PATTERN = Pattern.compile("^Signal-(Android|Desktop|iOS)/([^ ]+)( (.+))?$", Pattern.CASE_INSENSITIVE);

    private static final Map<ClientPlatform, Pattern> LEGACY_PATTERNS_BY_PLATFORM = new EnumMap<>(ClientPlatform.class);

    static {
        LEGACY_PATTERNS_BY_PLATFORM.put(ClientPlatform.ANDROID, Pattern.compile("^Signal-Android ([^ ]+)( (.+))?$", Pattern.CASE_INSENSITIVE));
        LEGACY_PATTERNS_BY_PLATFORM.put(ClientPlatform.DESKTOP, Pattern.compile("^Signal Desktop (.+)$", Pattern.CASE_INSENSITIVE));
        LEGACY_PATTERNS_BY_PLATFORM.put(ClientPlatform.IOS, Pattern.compile("^Signal/([^ ]+)( (.+))?$", Pattern.CASE_INSENSITIVE));
    }

    public static ClientPlatform getPlatformFromUserAgentString(final String userAgentString) throws UnrecognizedUserAgentException {
      if (userAgentString == null) {
        throw new UnrecognizedUserAgentException();
      }
      final Matcher standardUaMatcher = STANDARD_UA_PATTERN.matcher(userAgentString);

      if (standardUaMatcher.matches()) {
        return ClientPlatform.valueOf(standardUaMatcher.group(1).toUpperCase());
      } else {
        for (final Map.Entry<ClientPlatform, Pattern> entry : LEGACY_PATTERNS_BY_PLATFORM.entrySet()) {
          final ClientPlatform platform = entry.getKey();
          final Pattern pattern = entry.getValue();
          final Matcher legacyUaMatcher = pattern.matcher(userAgentString);

          if (legacyUaMatcher.matches()) {
            return platform;
          }
        }
      }

      throw new UnrecognizedUserAgentException();
    }
}
