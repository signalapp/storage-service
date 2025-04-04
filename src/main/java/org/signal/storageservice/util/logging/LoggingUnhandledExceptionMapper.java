/*
 * Copyright 2013-2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.util.logging;

import io.dropwizard.jersey.errors.LoggingExceptionMapper;
import jakarta.inject.Provider;
import jakarta.ws.rs.core.Context;
import org.glassfish.jersey.server.ContainerRequest;
import org.signal.storageservice.util.UriInfoUtil;

public class LoggingUnhandledExceptionMapper extends LoggingExceptionMapper<Throwable> {

  @Context
  private Provider<ContainerRequest> request;

  public LoggingUnhandledExceptionMapper() {
    super();
  }

  @Override
  protected String formatLogMessage(final long id, final Throwable exception) {
    String requestMethod = "unknown method";
    String userAgent = "missing";
    String requestPath = "/{unknown path}";
    try {
      // request shouldn’t be `null`, but it is technically possible
      requestMethod = request.get().getMethod();
      requestPath = UriInfoUtil.getPathTemplate(request.get().getUriInfo());
      userAgent = request.get().getHeaderString("user-agent");
    } catch (final Exception e) {
      logger.warn("Unexpected exception getting request details", e);
    }

    return String.format("%s at %s %s (%s)",
        super.formatLogMessage(id, exception),
        requestMethod,
        requestPath,
        userAgent) ;
  }

}
