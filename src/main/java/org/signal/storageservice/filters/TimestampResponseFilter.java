/*
 * Copyright 2025 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.filters;

import java.io.IOException;
import java.time.Clock;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import org.signal.storageservice.util.HeaderUtils;

/**
 * Injects a timestamp header into all outbound responses.
 */
public class TimestampResponseFilter implements Filter, ContainerResponseFilter {

  private final Clock clock;

  public TimestampResponseFilter(final Clock clock) {
    this.clock = clock;
  }

  @Override
  public void doFilter(final ServletRequest request, final ServletResponse response, final FilterChain chain)
      throws ServletException, IOException {

    if (response instanceof HttpServletResponse httpServletResponse) {
      httpServletResponse.setHeader(HeaderUtils.TIMESTAMP_HEADER, String.valueOf(clock.millis()));
    }

    chain.doFilter(request, response);
  }

  @Override
  public void filter(ContainerRequestContext requestContext, ContainerResponseContext responseContext) {
    // not using add() - it's ok to overwrite any existing header, and we don't want a multi-value
    responseContext.getHeaders().putSingle(HeaderUtils.TIMESTAMP_HEADER, String.valueOf(clock.millis()));
  }
}
