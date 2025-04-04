/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.providers;

import java.util.concurrent.CompletionException;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;
import org.glassfish.jersey.spi.ExceptionMappers;

@Provider
public class CompletionExceptionMapper implements ExceptionMapper<CompletionException> {

  @Context
  private ExceptionMappers exceptionMappers;

  @Override
  public Response toResponse(final CompletionException exception) {
    final Throwable cause = exception.getCause();

    if (cause != null) {
      return exceptionMappers.findMapping(cause).toResponse(cause);
    }

    return Response.serverError().build();
  }
}
