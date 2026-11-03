/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice;

import io.dropwizard.util.Resources;

/// Runs the storage service locally with test configuration (`config/test.yml`), backed by an in-memory Bigtable
/// emulator. This class may be run directly from a correctly configured IDE, or using the command
/// line:
///
/// `./mvnw clean integration-test -DskipTests=true -Ptest-server`
///
/// **NOTE: data is not persisted between runs, and features that depend on external services (e.g. metrics and log
/// export) are disabled.**
public class LocalStorageService {

  public static void main(final String[] args) throws Exception {
    new StorageService().run("server", Resources.getResource("config/test.yml").getPath());
  }
}
