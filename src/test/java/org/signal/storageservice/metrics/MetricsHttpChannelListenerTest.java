/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.metrics;

import com.google.common.net.HttpHeaders;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tag;
import org.eclipse.jetty.http.HttpURI;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.server.Response;
import org.glassfish.jersey.server.ExtendedUriInfo;
import org.glassfish.jersey.uri.UriTemplate;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class MetricsHttpChannelListenerTest {

  private MeterRegistry meterRegistry;
  private Counter requestCounter;
  private Counter responseBytesCounter;
  private MetricsHttpChannelListener listener;

  @BeforeEach
  void setup() {
    meterRegistry = mock(MeterRegistry.class);
    requestCounter = mock(Counter.class);
    responseBytesCounter = mock(Counter.class);

    //noinspection unchecked
    when(meterRegistry.counter(eq(MetricsHttpChannelListener.REQUEST_COUNTER_NAME), any(Iterable.class)))
        .thenReturn(requestCounter);

    //noinspection unchecked
    when(meterRegistry.counter(eq(MetricsHttpChannelListener.RESPONSE_BYTES_COUNTER_NAME), any(Iterable.class)))
        .thenReturn(responseBytesCounter);

    listener = new MetricsHttpChannelListener(meterRegistry);
  }

  @Test
  @SuppressWarnings("unchecked")
  void testRequests() {
    final String path = "/test";
    final String method = "GET";
    final int statusCode = 200;
    final long responseContentLength = 7;

    final HttpURI httpUri = mock(HttpURI.class);
    when(httpUri.getPath()).thenReturn(path);

    final Request request = mock(Request.class);
    when(request.getMethod()).thenReturn(method);
    when(request.getHeader(HttpHeaders.USER_AGENT)).thenReturn("Signal-Android/4.53.7 (Android 8.1)");
    when(request.getHttpURI()).thenReturn(httpUri);

    final Response response = mock(Response.class);
    when(response.getStatus()).thenReturn(statusCode);
    when(response.getContentCount()).thenReturn(responseContentLength);
    when(request.getResponse()).thenReturn(response);
    final ExtendedUriInfo extendedUriInfo = mock(ExtendedUriInfo.class);
    when(request.getAttribute(MetricsHttpChannelListener.URI_INFO_PROPERTY_NAME)).thenReturn(extendedUriInfo);
    when(extendedUriInfo.getMatchedTemplates()).thenReturn(List.of(new UriTemplate(path)));

    final ArgumentCaptor<Iterable<Tag>> tagCaptor = ArgumentCaptor.forClass(Iterable.class);

    listener.onComplete(request);

    verify(requestCounter).increment();
    verify(responseBytesCounter).increment(responseContentLength);

    verify(meterRegistry).counter(eq(MetricsHttpChannelListener.REQUEST_COUNTER_NAME), tagCaptor.capture());

    final Set<Tag> tags = new HashSet<>();
    for (final Tag tag : tagCaptor.getValue()) {
      tags.add(tag);
    }

    assertEquals(4, tags.size());
    assertTrue(tags.contains(Tag.of(MetricsHttpChannelListener.PATH_TAG, path)));
    assertTrue(tags.contains(Tag.of(MetricsHttpChannelListener.METHOD_TAG, method)));
    assertTrue(tags.contains(Tag.of(MetricsHttpChannelListener.STATUS_CODE_TAG, String.valueOf(statusCode))));
    assertTrue(tags.contains(Tag.of(UserAgentTagUtil.PLATFORM_TAG, "android")));
  }
}
