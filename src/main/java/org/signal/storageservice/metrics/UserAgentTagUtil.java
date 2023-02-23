/*
 * Copyright 2013-2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.metrics;

import com.vdurmont.semver4j.Semver;
import io.micrometer.core.instrument.Tag;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.signal.storageservice.util.Pair;
import org.signal.storageservice.util.ua.ClientPlatform;
import org.signal.storageservice.util.ua.UnrecognizedUserAgentException;
import org.signal.storageservice.util.ua.UserAgentUtil;

/**
 * Utility class for extracting platform/version metrics tags from User-Agent strings.
 */
public class UserAgentTagUtil {

    public static final  String    PLATFORM_TAG      = "platform";
    public static final  String    VERSION_TAG       = "clientVersion";
    static final         List<Tag> OVERFLOW_TAGS     = List.of(Tag.of(PLATFORM_TAG, "overflow"), Tag.of(VERSION_TAG, "overflow"));
    static final         List<Tag> UNRECOGNIZED_TAGS = List.of(Tag.of(PLATFORM_TAG, "unrecognized"), Tag.of(VERSION_TAG, "unrecognized"));

    private static final Map<ClientPlatform, Semver> MINIMUM_VERSION_BY_PLATFORM = new EnumMap<>(ClientPlatform.class);

    static {
        MINIMUM_VERSION_BY_PLATFORM.put(ClientPlatform.ANDROID, new Semver("4.0.0"));
        MINIMUM_VERSION_BY_PLATFORM.put(ClientPlatform.DESKTOP, new Semver("1.0.0"));
        MINIMUM_VERSION_BY_PLATFORM.put(ClientPlatform.IOS,     new Semver("3.0.0"));
    }

    static final         int                               MAX_VERSIONS  = 1_000;
    private static final Set<Pair<ClientPlatform, Semver>> SEEN_VERSIONS = new HashSet<>();

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
