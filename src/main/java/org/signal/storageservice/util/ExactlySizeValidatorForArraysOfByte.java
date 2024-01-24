/*
 * Copyright 2021 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.util;

public class ExactlySizeValidatorForArraysOfByte extends ExactlySizeValidator<byte[]> {

  @Override
  protected int size(final byte[] value) {
    return value == null ? 0 : value.length;
  }
}
