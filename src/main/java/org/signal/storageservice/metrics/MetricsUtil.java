/*
 * Copyright 2025 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.metrics;

import com.codahale.metrics.SharedMetricRegistries;
import io.dropwizard.core.setup.Environment;
import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.Tags;
import io.micrometer.core.instrument.binder.jvm.JvmMemoryMetrics;
import io.micrometer.core.instrument.binder.jvm.JvmThreadMetrics;
import io.micrometer.core.instrument.binder.system.FileDescriptorMetrics;
import io.micrometer.core.instrument.binder.system.ProcessorMetrics;
import io.micrometer.datadog.DatadogMeterRegistry;
import org.signal.storageservice.StorageServiceConfiguration;
import org.signal.storageservice.StorageServiceVersion;
import org.signal.storageservice.util.HostSupplier;

public class MetricsUtil {

  public static final String PREFIX = "storage";

  private static volatile boolean registeredMetrics = false;

  /**
   * Returns a dot-separated ('.') name for the given class and name parts
   */
  public static String name(Class<?> clazz, String... parts) {
    return name(clazz.getSimpleName(), parts);
  }

  private static String name(String name, String... parts) {
    final StringBuilder sb = new StringBuilder(PREFIX);
    sb.append(".").append(name);
    for (String part : parts) {
      sb.append(".").append(part);
    }
    return sb.toString();
  }

  public static void configureRegistries(final StorageServiceConfiguration config, final Environment environment) {

    if (registeredMetrics) {
      throw new IllegalStateException("Metric registries configured more than once");
    }

    registeredMetrics = true;

    SharedMetricRegistries.add(StorageMetrics.NAME, environment.metrics());

    {
      final DatadogMeterRegistry datadogMeterRegistry = new DatadogMeterRegistry(
              config.getDatadogConfiguration(), io.micrometer.core.instrument.Clock.SYSTEM);

      datadogMeterRegistry.config().commonTags(
              Tags.of(
                      "service", "storage",
                      "host", HostSupplier.getHost(),
                      "version", StorageServiceVersion.getServiceVersion(),
                      "env", config.getDatadogConfiguration().getEnvironment()));

      Metrics.addRegistry(datadogMeterRegistry);
    }
  }


  public static void registerSystemResourceMetrics(final Environment environment) {
    // Dropwizard metrics - some are temporarily duplicated for continuity
    environment.metrics().register(name(CpuUsageGauge.class, "cpu"), new CpuUsageGauge());
    environment.metrics().register(name(FreeMemoryGauge.class, "free_memory"), new FreeMemoryGauge());
    environment.metrics().register(name(NetworkSentGauge.class, "bytes_sent"), new NetworkSentGauge());
    environment.metrics().register(name(NetworkReceivedGauge.class, "bytes_received"), new NetworkReceivedGauge());
    environment.metrics().register(name(FileDescriptorGauge.class, "fd_count"), new FileDescriptorGauge());

    // Micrometer metrics
    new ProcessorMetrics().bindTo(Metrics.globalRegistry);
    new FreeMemoryGauge().bindTo(Metrics.globalRegistry);
    new FileDescriptorMetrics().bindTo(Metrics.globalRegistry);

    new JvmMemoryMetrics().bindTo(Metrics.globalRegistry);
    new JvmThreadMetrics().bindTo(Metrics.globalRegistry);
  }

}
