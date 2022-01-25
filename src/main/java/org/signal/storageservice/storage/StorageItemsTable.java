/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.storage;

import com.codahale.metrics.Counter;
import com.codahale.metrics.Histogram;
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
import org.apache.commons.codec.binary.Hex;
import org.signal.storageservice.auth.User;
import org.signal.storageservice.metrics.StorageMetrics;
import org.signal.storageservice.storage.protos.contacts.StorageItem;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.IntSummaryStatistics;
import java.util.LinkedList;
import java.util.List;
import java.util.OptionalInt;
import java.util.concurrent.CompletableFuture;

import static com.codahale.metrics.MetricRegistry.name;

public class StorageItemsTable extends Table {

  public static final String FAMILY      = "c";
  public static final String ROW_KEY     = "contact";

  public static final String COLUMN_DATA = "d";
  public static final String COLUMN_KEY  = "k";

  private final MetricRegistry metricRegistry       = SharedMetricRegistries.getOrCreate(StorageMetrics.NAME);
  private final Timer          getTimer             = metricRegistry.timer(name(StorageItemsTable.class, "get"            ));
  private final Timer          setTimer             = metricRegistry.timer(name(StorageItemsTable.class, "create"         ));
  private final Timer          getKeysToDeleteTimer = metricRegistry.timer(name(StorageItemsTable.class, "getKeysToDelete"));
  private final Timer          deleteKeysTimer      = metricRegistry.timer(name(StorageItemsTable.class, "deleteKeys"     ));
  private final Histogram      keySizeHistogram     = metricRegistry.histogram(name(StorageItemsTable.class, "getRowKeySize"));
  private final Histogram      keyListLengthHistogram = metricRegistry.histogram(name(StorageItemsTable.class, "getRowKeyListLength"));
  private final Counter        oversizeKeyCounter   = metricRegistry.counter(name(StorageItemsTable.class, "oversizeKeys"));

  private static final int MAX_ROW_KEY_SIZE = 4096;

  private static final Logger log = LoggerFactory.getLogger(StorageItemsTable.class);

  public StorageItemsTable(BigtableDataClient client, String tableId) {
    super(client, tableId);
  }

  public CompletableFuture<Void> set(User user, List<StorageItem> inserts, List<ByteString> deletes) {
    BulkMutation bulkMutation = BulkMutation.create(tableId);

    for (StorageItem insert : inserts) {
      bulkMutation.add(getRowKeyFor(user, insert.getKey()),
                       Mutation.create()
                               .setCell(FAMILY, ByteString.copyFromUtf8(COLUMN_DATA), 0, insert.getValue())
                               .setCell(FAMILY, ByteString.copyFromUtf8(COLUMN_KEY), 0, insert.getKey()));
    }

    for (ByteString delete : deletes) {
      bulkMutation.add(getRowKeyFor(user, delete), Mutation.create().deleteRow());
    }

    return toFuture(client.bulkMutateRowsAsync(bulkMutation), setTimer);
  }

  public CompletableFuture<Void> clear(User user) {
    Query query = Query.create(tableId);
    query.prefix(getRowKeyPrefixFor(user));

    Timer.Context                       getKeysContext = getKeysToDeleteTimer.time();
    CompletableFuture<List<ByteString>> future         = new CompletableFuture<>();

    client.readRowsAsync(query, new ResponseObserver<>() {
      private final List<ByteString> keys = new LinkedList<>();

      @Override
      public void onStart(StreamController streamController) {
      }

      @Override
      public void onResponse(Row row) {
        keys.add(row.getKey());
      }

      @Override
      public void onError(Throwable throwable) {
        getKeysContext.close();
        future.completeExceptionally(throwable);
      }

      @Override
      public void onComplete() {
        getKeysContext.close();
        future.complete(keys);
      }
    });

    return future.thenCompose(keysToDelete -> {
      if (keysToDelete.isEmpty()) return CompletableFuture.completedFuture(null);

      BulkMutation bulkMutation = BulkMutation.create(tableId);

      for (ByteString key : keysToDelete) {
        bulkMutation.add(key, Mutation.create().deleteRow());
      }

      return toFuture(client.bulkMutateRowsAsync(bulkMutation), deleteKeysTimer);
    });
  }

  public CompletableFuture<List<StorageItem>> get(User user, List<ByteString> keys) {
    if (keys.isEmpty()) throw new IllegalArgumentException("No keys");

    Timer.Context                        timerContext = getTimer.time();
    CompletableFuture<List<StorageItem>> future       = new CompletableFuture<>();
    List<StorageItem>                    results      = new LinkedList<>();
    Query                                query        = Query.create(tableId);

    keyListLengthHistogram.update(keys.size());

    for (ByteString key : keys) {
      final ByteString rowKey = getRowKeyFor(user, key);

      keySizeHistogram.update(rowKey.size());

      if (rowKey.size() > MAX_ROW_KEY_SIZE) {
        oversizeKeyCounter.inc();
      }

      query.rowKey(rowKey);
    }

    client.readRowsAsync(query, new ResponseObserver<>() {
      @Override
      public void onStart(StreamController controller) { }

      @Override
      public void onResponse(Row row) {
        ByteString key   = row.getCells().stream().filter(cell -> COLUMN_KEY.equals(cell.getQualifier().toStringUtf8())).findFirst().orElseThrow().getValue ();
        ByteString value = row.getCells().stream().filter(cell -> COLUMN_DATA.equals(cell.getQualifier().toStringUtf8())).findFirst().orElseThrow().getValue();

        results.add(StorageItem.newBuilder()
                               .setKey(key)
                               .setValue(value)
                               .build());
      }

      @Override
      public void onError(Throwable t) {
        timerContext.close();
        future.completeExceptionally(t);

        final IntSummaryStatistics summaryStatistics = keys.stream()
            .map(key -> getRowKeyFor(user, key))
            .mapToInt(ByteString::size)
            .summaryStatistics();

        log.warn("Read request failed; row keys: {}, max key length: {}, min key length: {}, total row key size: {}",
            summaryStatistics.getCount(), summaryStatistics.getMax(), summaryStatistics.getMin(), summaryStatistics.getSum());
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
    return ByteString.copyFromUtf8(user.getUuid().toString() + "#" + ROW_KEY + "#" + Hex.encodeHexString(key.toByteArray()));
  }

  private ByteString getRowKeyPrefixFor(User user) {
    return ByteString.copyFromUtf8(user.getUuid().toString() + "#" + ROW_KEY + "#");
  }

}
