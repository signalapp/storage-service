/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.storage;

import static com.codahale.metrics.MetricRegistry.name;

import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.SharedMetricRegistries;
import com.codahale.metrics.Timer;
import com.google.api.gax.rpc.ResponseObserver;
import com.google.api.gax.rpc.StreamController;
import com.google.cloud.bigtable.data.v2.BigtableDataClient;
import com.google.cloud.bigtable.data.v2.models.BulkMutation;
import com.google.cloud.bigtable.data.v2.models.Mutation;
import com.google.cloud.bigtable.data.v2.models.Query;
import com.google.cloud.bigtable.data.v2.models.Row;
import com.google.protobuf.ByteString;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import org.apache.commons.codec.binary.Hex;
import org.signal.storageservice.auth.User;
import org.signal.storageservice.metrics.StorageMetrics;
import org.signal.storageservice.storage.protos.contacts.StorageItem;

public class StorageItemsTable extends Table {

  public static final String FAMILY = "c";
  public static final String ROW_KEY = "contact";

  public static final String COLUMN_DATA = "d";
  public static final String COLUMN_KEY = "k";

  public static final int MAX_MUTATIONS = 100_000;
  public static final int MUTATIONS_PER_INSERT = 2;

  private final MetricRegistry metricRegistry = SharedMetricRegistries.getOrCreate(StorageMetrics.NAME);
  private final Timer getTimer = metricRegistry.timer(name(StorageItemsTable.class, "get"));
  private final Timer setTimer = metricRegistry.timer(name(StorageItemsTable.class, "create"));
  private final Timer getKeysToDeleteTimer = metricRegistry.timer(name(StorageItemsTable.class, "getKeysToDelete"));
  private final Timer deleteKeysTimer = metricRegistry.timer(name(StorageItemsTable.class, "deleteKeys"));

  public StorageItemsTable(BigtableDataClient client, String tableId) {
    super(client, tableId);
  }

  public CompletableFuture<Void> set(User user, List<StorageItem> inserts, List<ByteString> deletes) {
    BulkMutation bulkMutation = BulkMutation.create(tableId);

    for (StorageItem insert : inserts) {
      bulkMutation.add(getRowKeyFor(user, insert.getKey()),
          Mutation.create()
              // each setCell() counts as mutation. If the below code changes, update MUTATIONS_PER_INSERT
              .setCell(FAMILY, ByteString.copyFromUtf8(COLUMN_DATA), 0, insert.getValue())
              .setCell(FAMILY, ByteString.copyFromUtf8(COLUMN_KEY), 0, insert.getKey()));
    }

    for (ByteString delete : deletes) {
      bulkMutation.add(getRowKeyFor(user, delete), Mutation.create().deleteRow());
    }

    return toFuture(client.bulkMutateRowsAsync(bulkMutation), setTimer);
  }

  public CompletableFuture<Void> clear(User user) {
    final Query query = Query.create(tableId);
    query.prefix(getRowKeyPrefixFor(user));
    query.limit(MAX_MUTATIONS);

    final CompletableFuture<BulkMutation> fetchRowsFuture = new CompletableFuture<>();

    final Timer.Context getKeysToDeleteTimerContext = getKeysToDeleteTimer.time();
    fetchRowsFuture.whenComplete((result, throwable) -> getKeysToDeleteTimerContext.close());

    client.readRowsAsync(query, new ResponseObserver<>() {
      private final BulkMutation bulkMutation = BulkMutation.create(tableId);

      @Override
      public void onStart(final StreamController streamController) {
      }

      @Override
      public void onResponse(final Row row) {
        bulkMutation.add(row.getKey(), Mutation.create().deleteRow());
      }

      @Override
      public void onError(final Throwable throwable) {
        fetchRowsFuture.completeExceptionally(throwable);
      }

      @Override
      public void onComplete() {
        fetchRowsFuture.complete(bulkMutation);
      }
    });

    return fetchRowsFuture.thenCompose(bulkMutation -> bulkMutation.getEntryCount() == 0
        ? CompletableFuture.completedFuture(null)
        : toFuture(client.bulkMutateRowsAsync(bulkMutation), deleteKeysTimer).thenCompose(ignored -> clear(user)));
  }

  public CompletableFuture<List<StorageItem>> get(User user, List<ByteString> keys) {
    if (keys.isEmpty()) {
      throw new IllegalArgumentException("No keys");
    }

    Timer.Context timerContext = getTimer.time();
    CompletableFuture<List<StorageItem>> future = new CompletableFuture<>();
    List<StorageItem> results = new LinkedList<>();
    Query query = Query.create(tableId);

    for (ByteString key : keys) {
      query.rowKey(getRowKeyFor(user, key));
    }

    client.readRowsAsync(query, new ResponseObserver<>() {
      @Override
      public void onStart(StreamController controller) {
      }

      @Override
      public void onResponse(Row row) {
        ByteString key = row.getCells().stream().filter(cell -> COLUMN_KEY.equals(cell.getQualifier().toStringUtf8()))
            .findFirst().orElseThrow().getValue();
        ByteString value = row.getCells().stream()
            .filter(cell -> COLUMN_DATA.equals(cell.getQualifier().toStringUtf8())).findFirst().orElseThrow()
            .getValue();

        results.add(StorageItem.newBuilder()
            .setKey(key)
            .setValue(value)
            .build());
      }

      @Override
      public void onError(Throwable t) {
        timerContext.close();
        future.completeExceptionally(t);
      }

      @Override
      public void onComplete() {
        timerContext.close();
        future.complete(results);
      }
    });

    return future;
  }

  private ByteString getRowKeyFor(User user, ByteString key) {
    return ByteString.copyFromUtf8(
        user.getUuid().toString() + "#" + ROW_KEY + "#" + Hex.encodeHexString(key.toByteArray()));
  }

  private ByteString getRowKeyPrefixFor(User user) {
    return ByteString.copyFromUtf8(user.getUuid().toString() + "#" + ROW_KEY + "#");
  }

}
