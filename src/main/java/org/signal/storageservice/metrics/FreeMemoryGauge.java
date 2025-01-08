/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.metrics;

import com.codahale.metrics.Gauge;
import com.sun.management.OperatingSystemMXBean;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.binder.MeterBinder;

import java.lang.management.ManagementFactory;

import static org.signal.storageservice.metrics.MetricsUtil.name;

public class FreeMemoryGauge implements Gauge<Long>, MeterBinder {

  private final OperatingSystemMXBean operatingSystemMXBean;

  public FreeMemoryGauge() {
    this.operatingSystemMXBean = (com.sun.management.OperatingSystemMXBean)
        ManagementFactory.getOperatingSystemMXBean();
  }

  @Override
  public Long getValue() {
    return operatingSystemMXBean.getFreeMemorySize();
  }

  @Override
  public void bindTo(final MeterRegistry registry) {
    io.micrometer.core.instrument.Gauge.builder(name(FreeMemoryGauge.class, "freeMemory"), operatingSystemMXBean,
            OperatingSystemMXBean::getFreeMemorySize)
        .register(registry);

  }
}
