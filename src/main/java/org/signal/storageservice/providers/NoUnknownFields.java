/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.providers;

import jakarta.validation.Constraint;
import jakarta.validation.Payload;
import java.lang.annotation.Documented;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.FIELD;
import static java.lang.annotation.ElementType.PARAMETER;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

@Documented
@Retention(RUNTIME)
@Target({FIELD, PARAMETER})
@Constraint(validatedBy = {NoUnknownFieldsValidator.class})
public @interface NoUnknownFields {
  String message() default "{org.signal.storageservice.providers.NoUnknownFields.message}";
  Class<?>[] groups() default {};
  Class<? extends Payload>[] payload() default {};

  boolean recursive() default true;
}
