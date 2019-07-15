/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.metrics;


import com.codahale.metrics.Gauge;

import java.io.File;

public class FileDescriptorGauge implements Gauge<Integer> {
  @Override
  public Integer getValue() {
    File file = new File("/proc/self/fd");

    if (file.isDirectory() && file.exists()) {
      return file.list().length;
    }

    return 0;
  }
}
