/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.util;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

public class CollectionUtil {

  public static <T> boolean containsAny(Collection<T> first, Collection<T> second) {
    return containsAny(new HashSet<>(first), second);
  }

  public static <T> boolean containsAny(Set<T> first, Collection<T> second) {
    for (T item : second) {
      if (first.contains(item)) return true;
    }

    return false;
  }

  public static <T> boolean containsDuplicates(Collection<T> items) {
    Set<T> contents = new HashSet<>();

    for (T item : items) {
      if (!contents.add(item)) {
        return true;
      }
    }

    return false;
  }



}
