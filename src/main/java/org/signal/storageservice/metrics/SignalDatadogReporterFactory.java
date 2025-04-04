/*
 * This is derived from Coursera's dropwizard datadog reporter.
 * https://github.com/coursera/metrics-datadog
 */

package org.signal.storageservice.metrics;

import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.ScheduledReporter;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeName;
import io.dropwizard.metrics.common.BaseReporterFactory;
import java.util.ArrayList;
import java.util.EnumSet;
import java.util.List;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;
import org.coursera.metrics.datadog.DatadogReporter;
import org.coursera.metrics.datadog.DatadogReporter.Expansion;
import org.coursera.metrics.datadog.DefaultMetricNameFormatterFactory;
import org.coursera.metrics.datadog.DynamicTagsCallbackFactory;
import org.coursera.metrics.datadog.MetricNameFormatterFactory;
import org.coursera.metrics.datadog.transport.AbstractTransportFactory;
import org.signal.storageservice.StorageServiceVersion;
import org.signal.storageservice.util.HostSupplier;

@JsonTypeName("signal-datadog")
public class SignalDatadogReporterFactory extends BaseReporterFactory {

  @JsonProperty
  private String host = null;

  @JsonProperty
  private List<String> tags = null;

  @Valid
  @JsonProperty
  private DynamicTagsCallbackFactory dynamicTagsCallback = null;

  @JsonProperty
  private String prefix = null;

  @Valid
  @NotNull
  @JsonProperty
  private EnumSet<Expansion> expansions = EnumSet.of(
      Expansion.COUNT,
      Expansion.MIN,
      Expansion.MAX,
      Expansion.MEAN,
      Expansion.MEDIAN,
      Expansion.P95,
      Expansion.P99
  );

  @Valid
  @NotNull
  @JsonProperty
  private MetricNameFormatterFactory metricNameFormatter = new DefaultMetricNameFormatterFactory();

  @Valid
  @NotNull
  @JsonProperty
  private AbstractTransportFactory transport = null;

  @Override
  public ScheduledReporter build(final MetricRegistry registry) {

    final List<String> combinedTags;
    final String versionTag = "version:" + StorageServiceVersion.getServiceVersion();

    if (tags != null) {
      combinedTags = new ArrayList<>(tags);
      combinedTags.add(versionTag);
    } else {
      combinedTags = new ArrayList<>((List.of(versionTag)));
    }

    return DatadogReporter.forRegistry(registry)
        .withTransport(transport.build())
        .withHost(HostSupplier.getHost())
        .withTags(combinedTags)
        .withPrefix(prefix)
        .withExpansions(expansions)
        .withMetricNameFormatter(metricNameFormatter.build())
        .withDynamicTagCallback(dynamicTagsCallback != null ? dynamicTagsCallback.build() : null)
        .filter(getFilter())
        .convertDurationsTo(getDurationUnit())
        .convertRatesTo(getRateUnit())
        .build();
  }
}
