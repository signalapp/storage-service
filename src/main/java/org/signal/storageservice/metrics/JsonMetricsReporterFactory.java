/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.metrics;

import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.ScheduledReporter;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;
import io.dropwizard.metrics.common.BaseReporterFactory;

import javax.validation.constraints.NotNull;
import java.net.UnknownHostException;

@JsonTypeName("json")
public class JsonMetricsReporterFactory extends BaseReporterFactory {

  @JsonProperty
  @NotNull
  private String hostname;

  @JsonProperty
  @NotNull
  private String token;

  @JsonProperty
  @NotNull
  private String prefix;

  @Override
  public ScheduledReporter build(MetricRegistry metricRegistry) {
    try {
      return JsonMetricsReporter.forRegistry(metricRegistry)
                                .withHostname(hostname)
                                .withToken(token)
                                .withReportingPrefix(prefix)
                                .convertRatesTo(getRateUnit())
                                .convertDurationsTo(getDurationUnit())
                                .filter(getFilter())
                                .build();
    } catch (UnknownHostException e) {
      throw new IllegalArgumentException(e);
    }
  }
}
