/*
 * Copyright 2013-2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice;

public class StorageServiceVersion {

  private static final String VERSION = "${project.version}";

  public static String getServiceVersion() {
    return VERSION;
  }
}
