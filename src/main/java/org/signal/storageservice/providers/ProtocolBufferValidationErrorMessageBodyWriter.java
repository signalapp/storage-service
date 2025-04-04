/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.providers;

import io.dropwizard.jersey.validation.ValidationErrorMessage;

import jakarta.ws.rs.Produces;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.ext.MessageBodyWriter;
import jakarta.ws.rs.ext.Provider;
import java.io.IOException;
import java.io.OutputStream;
import java.lang.annotation.Annotation;
import java.lang.reflect.Type;

@Provider
@Produces({
  ProtocolBufferMediaType.APPLICATION_PROTOBUF,
  ProtocolBufferMediaType.APPLICATION_PROTOBUF_TEXT,
  ProtocolBufferMediaType.APPLICATION_PROTOBUF_JSON
})
public class ProtocolBufferValidationErrorMessageBodyWriter implements MessageBodyWriter<ValidationErrorMessage> {
  @Override
  public boolean isWriteable(Class<?> type, Type genericType, Annotation[] annotations, MediaType mediaType) {
    return ValidationErrorMessage.class.isAssignableFrom(type);
  }

  @Override
  public long getSize(ValidationErrorMessage validationErrorMessage, Class<?> type, Type genericType, Annotation[] annotations, MediaType mediaType) {
    return 0;
  }

  @Override
  public void writeTo(ValidationErrorMessage validationErrorMessage, Class<?> type, Type genericType, Annotation[] annotations, MediaType mediaType, MultivaluedMap<String, Object> httpHeaders, OutputStream entityStream) throws IOException, WebApplicationException {
  }
}
