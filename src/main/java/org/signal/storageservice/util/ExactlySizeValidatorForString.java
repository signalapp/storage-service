/*
 * Copyright 2013-2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.util;


public class ExactlySizeValidatorForString extends ExactlySizeValidator<String> {

  @Override
  protected int size(final String value) {
    return value == null ? 0 : value.length();
  }
}
