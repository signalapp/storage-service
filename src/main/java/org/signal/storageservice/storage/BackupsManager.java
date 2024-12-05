/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.storage;

import com.google.cloud.bigtable.admin.v2.models.Backup;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

public interface BackupsManager {
  CompletableFuture<Map<String, Backup>> createBackups();
}
