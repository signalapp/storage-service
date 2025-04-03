package org.signal.storageservice.metrics;

import com.codahale.metrics.MetricRegistry;
import com.google.common.annotations.VisibleForTesting;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.Tags;
import java.util.List;
import org.glassfish.jersey.server.monitoring.RequestEvent;
import org.glassfish.jersey.server.monitoring.RequestEventListener;
import org.signal.storageservice.util.UriInfoUtil;
import org.signal.storageservice.util.ua.ClientPlatform;
import org.signal.storageservice.util.ua.UnrecognizedUserAgentException;
import org.signal.storageservice.util.ua.UserAgentUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Gathers and reports request-level metrics.
 */
public class MetricsRequestEventListener implements RequestEventListener {

  static final String REQUEST_COUNTER_NAME = MetricRegistry.name(MetricsRequestEventListener.class, "request");
  static final String RESPONSE_BYTES_COUNTER_NAME = MetricRegistry.name(MetricsRequestEventListener.class, "responseBytes");

  static final String PATH_TAG = "path";
  static final String METHOD_TAG = "method";
  static final String STATUS_CODE_TAG = "status";
  static final String PLATFORM_TAG = "platform";

  private static final Logger log = LoggerFactory.getLogger(MetricsRequestEventListener.class);

  private final MeterRegistry meterRegistry;

  public MetricsRequestEventListener() {
    this(Metrics.globalRegistry);
  }

  @VisibleForTesting
  MetricsRequestEventListener(final MeterRegistry meterRegistry) {
    this.meterRegistry = meterRegistry;
  }

  @Override
  public void onEvent(final RequestEvent event) {
    if (event.getType() == RequestEvent.Type.FINISHED) {
      if (!event.getUriInfo().getMatchedTemplates().isEmpty()) {
        final String path = UriInfoUtil.getPathTemplate(event.getUriInfo());
        final String method = event.getContainerRequest().getMethod();

        Tags tags = Tags.of(
            PATH_TAG, path,
            METHOD_TAG, method,
            STATUS_CODE_TAG, String.valueOf(event.getContainerResponse().getStatus()));

        final List<String> userAgentValues = event.getContainerRequest().getRequestHeader("User-Agent");

        if (userAgentValues != null && !userAgentValues.isEmpty()) {
          try {
            final ClientPlatform platform = UserAgentUtil.getPlatformFromUserAgentString(userAgentValues.getFirst());
            tags = tags.and(PLATFORM_TAG, platform.name().toLowerCase());
          } catch (UnrecognizedUserAgentException e) {
            tags = tags.and(PLATFORM_TAG, "unknown");
          }
        }

        meterRegistry.counter(REQUEST_COUNTER_NAME, tags).increment();

        final int responseLength = event.getContainerResponse().getLength();

        // Response length can be -1 to indicate "unknown"
        if (responseLength >= 0) {
          meterRegistry.counter(RESPONSE_BYTES_COUNTER_NAME, tags).increment(event.getContainerResponse().getLength());
        } else {
          log.warn("Unknown response size for {} {}", method, path);
        }
      }
    }
  }
}
