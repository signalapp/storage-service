/*
 * Copyright 2025 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.util;

import com.google.cloud.MetadataConfig;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Optional;
import java.util.UUID;
import org.apache.commons.lang3.StringUtils;

/**
 * This class attempts to supply a meaningful host string for use in metrics and logging attribution. It prioritizes the
 * hostname value via {@link InetAddress#getHostName()}, but falls back to:
 * <ul>
 *   <li>an instance ID from cloud provider metadata</li>
 *   <li>random ID if no cloud provider instance ID is available</li>
 * </ul>
 * <p>
 * In the current implementation, only <a href="https://cloud.google.com/">GCP</a> is supported, but support for other
 * platforms may be added in the future.
 */
public class HostSupplier {

  private static final String FALLBACK_INSTANCE_ID = UUID.randomUUID().toString();

  public static String getHost() {
    return getHostName()
        .orElse(StringUtils.defaultIfBlank(MetadataConfig.getInstanceId(), FALLBACK_INSTANCE_ID));
  }

  private static Optional<String> getHostName() {
    try {
      final String hostname = InetAddress.getLocalHost().getHostName();
      if ("localhost".equals(hostname)) {
        return Optional.empty();
      }

      return Optional.ofNullable(hostname);
    } catch (UnknownHostException e) {
      return Optional.empty();
    }
  }
}
