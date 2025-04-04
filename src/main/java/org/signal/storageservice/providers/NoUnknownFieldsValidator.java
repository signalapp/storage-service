/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.providers;

import com.google.protobuf.Descriptors;
import com.google.protobuf.Message;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;
import java.util.Map;

public class NoUnknownFieldsValidator implements ConstraintValidator<NoUnknownFields, Message> {

  private boolean recursive;

  @Override
  public void initialize(NoUnknownFields constraintAnnotation) {
    recursive = constraintAnnotation.recursive();
  }

  @Override
  public boolean isValid(Message value, ConstraintValidatorContext context) {
    if (!value.getUnknownFields().asMap().isEmpty()) return false;
    if (recursive) {
      for (Map.Entry<Descriptors.FieldDescriptor, Object> entry : value.getAllFields().entrySet()) {
        if (entry.getKey().getType() == Descriptors.FieldDescriptor.Type.MESSAGE ||
            entry.getKey().getType() == Descriptors.FieldDescriptor.Type.GROUP) {
          if (entry.getKey().isRepeated()) {
            //noinspection unchecked
            for (Message message : (Iterable<? extends Message>) entry.getValue()) {
              if (!isValid(message, context)) return false;
            }
          } else {
            if (!isValid((Message) entry.getValue(), context)) return false;
          }
        }
      }
    }
    return true;
  }
}
