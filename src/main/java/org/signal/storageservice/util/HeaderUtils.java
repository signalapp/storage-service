/*
 * Copyright 2025 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class HeaderUtils {

  private static final Logger logger = LoggerFactory.getLogger(HeaderUtils.class);

  public static final String TIMESTAMP_HEADER = "X-Signal-Timestamp";
  
  private HeaderUtils() {
    // utility class
  }

}
