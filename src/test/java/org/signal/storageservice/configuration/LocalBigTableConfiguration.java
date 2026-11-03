/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.configuration;

import com.fasterxml.jackson.annotation.JsonTypeName;
import com.google.cloud.bigtable.admin.v2.BigtableTableAdminClient;
import com.google.cloud.bigtable.admin.v2.BigtableTableAdminSettings;
import com.google.cloud.bigtable.admin.v2.models.CreateTableRequest;
import com.google.cloud.bigtable.data.v2.BigtableDataClient;
import com.google.cloud.bigtable.data.v2.BigtableDataSettings;
import com.google.cloud.bigtable.emulator.v2.Emulator;
import java.io.IOException;
import java.util.Map;
import java.util.concurrent.TimeoutException;
import org.signal.storageservice.storage.GroupLogTable;
import org.signal.storageservice.storage.GroupsTable;
import org.signal.storageservice.storage.StorageItemsTable;
import org.signal.storageservice.storage.StorageManifestsTable;

/// Starts a local, in-memory Bigtable [Emulator] and creates all configured tables
@JsonTypeName("local")
public class LocalBigTableConfiguration extends BigTableConfiguration {

  @Override
  public BigtableDataClient buildDataClient() throws IOException {
    final Emulator emulator = Emulator.createBundled();

    try {
      emulator.start();
    } catch (final InterruptedException | TimeoutException e) {
      throw new IOException("Failed to start Bigtable emulator", e);
    }

    Runtime.getRuntime().addShutdownHook(new Thread(emulator::stop));

    try (final BigtableTableAdminClient tableAdminClient = BigtableTableAdminClient.create(
        BigtableTableAdminSettings.newBuilderForEmulator(emulator.getPort())
            .setProjectId(getProjectId())
            .setInstanceId(getInstanceId())
            .build())) {

      Map.of(getContactManifestsTableId(), StorageManifestsTable.FAMILY,
              getContactsTableId(), StorageItemsTable.FAMILY,
              getGroupsTableId(), GroupsTable.FAMILY,
              getGroupLogsTableId(), GroupLogTable.FAMILY)
          .forEach((tableId, family) -> tableAdminClient.createTable(CreateTableRequest.of(tableId).addFamily(family)));
    }

    return BigtableDataClient.create(BigtableDataSettings.newBuilderForEmulator(emulator.getPort())
        .setProjectId(getProjectId())
        .setInstanceId(getInstanceId())
        .build());
  }
}
