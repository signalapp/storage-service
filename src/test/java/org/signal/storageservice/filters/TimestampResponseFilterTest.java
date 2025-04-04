/*
 * Copyright 2025 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.filters;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.core.MultivaluedMap;
import org.junit.jupiter.api.Test;
import org.signal.storageservice.util.HeaderUtils;

class TimestampResponseFilterTest {

  private static final long EPOCH_MILLIS = 1738182156000L;

  private static final Clock CLOCK = Clock.fixed(Instant.ofEpochMilli(EPOCH_MILLIS), ZoneId.systemDefault());

  @Test
  void testJerseyFilter() {
    final ContainerRequestContext requestContext = mock(ContainerRequestContext.class);
    final ContainerResponseContext responseContext = mock(ContainerResponseContext.class);
    final MultivaluedMap<String, Object> headers = org.glassfish.jersey.message.internal.HeaderUtils.createOutbound();
    when(responseContext.getHeaders()).thenReturn(headers);

    new TimestampResponseFilter(CLOCK).filter(requestContext, responseContext);

    assertTrue(headers.containsKey(HeaderUtils.TIMESTAMP_HEADER));
    assertEquals(1, headers.get(HeaderUtils.TIMESTAMP_HEADER).size());
    assertEquals(String.valueOf(EPOCH_MILLIS), headers.get(HeaderUtils.TIMESTAMP_HEADER).get(0));
  }

  @Test
  void testServletFilter() throws Exception {
    final HttpServletRequest request = mock(HttpServletRequest.class);
    final HttpServletResponse response = mock(HttpServletResponse.class);

    new TimestampResponseFilter(CLOCK).doFilter(request, response, mock(FilterChain.class));

    verify(response).setHeader(eq(HeaderUtils.TIMESTAMP_HEADER), eq(String.valueOf(EPOCH_MILLIS)));
  }
}
