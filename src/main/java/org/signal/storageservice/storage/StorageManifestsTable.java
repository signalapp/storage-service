/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.storage;

import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.SharedMetricRegistries;
import com.codahale.metrics.Timer;
import com.google.cloud.bigtable.data.v2.BigtableDataClient;
import com.google.cloud.bigtable.data.v2.models.Filters;
import com.google.cloud.bigtable.data.v2.models.Mutation;
import com.google.cloud.bigtable.data.v2.models.Row;
import com.google.cloud.bigtable.data.v2.models.RowCell;
import com.google.cloud.bigtable.data.v2.models.RowMutation;
import com.google.protobuf.ByteString;
import org.signal.storageservice.auth.User;
import org.signal.storageservice.metrics.StorageMetrics;
import org.signal.storageservice.storage.protos.contacts.StorageManifest;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

import static com.codahale.metrics.MetricRegistry.name;

public class StorageManifestsTable extends Table {

  static final String FAMILY         = "m";

  static final String COLUMN_VERSION = "ver";
  static final String COLUMN_DATA    = "dat";

  private final MetricRegistry metricRegistry       = SharedMetricRegistries.getOrCreate(StorageMetrics.NAME);
  private final Timer          getTimer             = metricRegistry.timer(name(StorageManifestsTable.class, "get"            ));
  private final Timer          setTimer             = metricRegistry.timer(name(StorageManifestsTable.class, "create"         ));
  private final Timer          getIfNotVersionTimer = metricRegistry.timer(name(StorageManifestsTable.class, "getIfNotVersion"));
  private final Timer          deleteManifestTimer  = metricRegistry.timer(name(StorageManifestsTable.class, "delete"         ));

  public StorageManifestsTable(BigtableDataClient client, String tableId) {
    super(client, tableId);
  }

  /**
   * Updates the {@link StorageManifest} for the given user. The update is applied if and only if no manifest exists for
   * the given user <em>or</em> the given {@code manifest}'s version is exactly one greater than the version of the
   * existing manifest.
   *
   * @param user the user for whom to store an updated manifest
   * @param manifest the updated manifest to store
   *
   * @return a future that yields {@code true} if the manifest was updated or {@code false} otherwise
   */
  public CompletableFuture<Boolean> set(User user, StorageManifest manifest) {
    Mutation updateManifestMutation = Mutation.create()
                                              .setCell(FAMILY, COLUMN_VERSION, 0, String.valueOf(manifest.getVersion()))
                                              .setCell(FAMILY, ByteString.copyFromUtf8(COLUMN_DATA), 0, manifest.getValue());

    return setIfValueOrEmpty(setTimer, getRowKeyForManifest(user), FAMILY, COLUMN_VERSION, String.valueOf(manifest.getVersion() - 1), updateManifestMutation);
  }

  public CompletableFuture<Optional<StorageManifest>> get(User user) {
    return toFuture(client.readRowAsync(tableId, getRowKeyForManifest(user)), getTimer).thenApply(this::getManifestFromRow);
  }

  public CompletableFuture<Optional<StorageManifest>> getIfNotVersion(User user, long version) {
    return toFuture(client.readRowAsync(tableId, getRowKeyForManifest(user), Filters.FILTERS.condition(Filters.FILTERS.chain()
                                                                                                                      .filter(Filters.FILTERS.key().exactMatch(getRowKeyForManifest(user)))
                                                                                                                      .filter(Filters.FILTERS.family().exactMatch(FAMILY))
                                                                                                                      .filter(Filters.FILTERS.qualifier().exactMatch(COLUMN_VERSION))
                                                                                                                      .filter(Filters.FILTERS.value().exactMatch(String.valueOf(version))))
                                                                                            .then(Filters.FILTERS.block())
                                                                                            .otherwise(Filters.FILTERS.pass())),
                    getIfNotVersionTimer).thenApply(this::getManifestFromRow);
  }

  public CompletableFuture<Void> clear(final User user) {
    return toFuture(client.mutateRowAsync(RowMutation.create(tableId, getRowKeyForManifest(user)).deleteRow()), deleteManifestTimer);
  }

  private ByteString getRowKeyForManifest(User user) {
    return ByteString.copyFromUtf8(user.getUuid().toString() + "#manifest");
  }

  private Optional<StorageManifest> getManifestFromRow(Row row) {
    if (row == null) return Optional.empty();

    StorageManifest.Builder contactsManifest = StorageManifest.newBuilder();
    List<RowCell>           manifestCells    = row.getCells(FAMILY);

    contactsManifest.setVersion(Long.valueOf(manifestCells.stream().filter(cell -> COLUMN_VERSION.equals(cell.getQualifier().toStringUtf8())).findFirst().orElseThrow().getValue().toStringUtf8()));
    contactsManifest.setValue(manifestCells.stream().filter(cell -> COLUMN_DATA.equals(cell.getQualifier().toStringUtf8())).findFirst().orElseThrow().getValue());

    return Optional.of(contactsManifest.build());
  }

}
