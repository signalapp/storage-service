/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.metrics;

import com.codahale.metrics.Gauge;
import com.sun.management.OperatingSystemMXBean;

import java.lang.management.ManagementFactory;

public class CpuUsageGauge implements Gauge<Integer> {
  @Override
  public Integer getValue() {
    OperatingSystemMXBean mbean = (OperatingSystemMXBean)
        ManagementFactory.getOperatingSystemMXBean();

    return (int) Math.ceil(mbean.getCpuLoad() * 100);
  }
}
