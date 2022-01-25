package org.signal.storageservice.metrics;

import com.codahale.metrics.MetricRegistry;
import com.google.common.annotations.VisibleForTesting;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.Tag;
import io.micrometer.core.instrument.Tags;
import org.glassfish.jersey.server.monitoring.RequestEvent;
import org.glassfish.jersey.server.monitoring.RequestEventListener;
import org.signal.storageservice.util.UriInfoUtil;
import org.signal.storageservice.util.ua.ClientPlatform;
import org.signal.storageservice.util.ua.UnrecognizedUserAgentException;
import org.signal.storageservice.util.ua.UserAgentUtil;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Gathers and reports request-level metrics.
 */
public class MetricsRequestEventListener implements RequestEventListener {

  public static final String REQUEST_COUNTER_NAME = MetricRegistry.name(MetricsRequestEventListener.class, "request");

  static final String PATH_TAG = "path";
  static final String METHOD_TAG = "method";
  static final String STATUS_CODE_TAG = "status";
  static final String PLATFORM_TAG = "platform";

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
        Tags tags = Tags.of(
            PATH_TAG, UriInfoUtil.getPathTemplate(event.getUriInfo()),
            METHOD_TAG, event.getContainerRequest().getMethod(),
            STATUS_CODE_TAG, String.valueOf(event.getContainerResponse().getStatus()));

        final List<String> userAgentValues = event.getContainerRequest().getRequestHeader("User-Agent");

        if (!userAgentValues.isEmpty()) {
          try {
            final ClientPlatform platform = UserAgentUtil.getPlatformFromUserAgentString(userAgentValues.get(0));
            tags = tags.and(PLATFORM_TAG, platform.name().toLowerCase());
          } catch (UnrecognizedUserAgentException e) {
            tags = tags.and(PLATFORM_TAG, "unknown");
          }
        }

        meterRegistry.counter(REQUEST_COUNTER_NAME, tags).increment();
      }
    }
  }
}
