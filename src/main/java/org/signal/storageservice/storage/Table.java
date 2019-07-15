/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.storage;

import com.codahale.metrics.Timer;
import com.google.api.core.ApiFuture;
import com.google.api.core.ApiFutureCallback;
import com.google.api.core.ApiFutures;
import com.google.cloud.bigtable.data.v2.BigtableDataClient;
import com.google.cloud.bigtable.data.v2.models.ConditionalRowMutation;
import com.google.cloud.bigtable.data.v2.models.Mutation;
import com.google.common.util.concurrent.MoreExecutors;
import com.google.protobuf.ByteString;

import java.util.concurrent.CompletableFuture;

import static com.google.cloud.bigtable.data.v2.models.Filters.FILTERS;

abstract class Table {

  final BigtableDataClient client;
  final String             tableId;

  public Table(BigtableDataClient client, String tableId) {
    this.client  = client;
    this.tableId = tableId;
  }

  CompletableFuture<Boolean> setIfValueOrEmpty(Timer timer, ByteString rowId, String columnFamily, String columnName, String columnEquals, Mutation mutation) {
    return setIfValue(timer, rowId, columnFamily, columnName, columnEquals, mutation).thenCompose(mutated -> {
      if (mutated) return CompletableFuture.completedFuture(true);
      else         return setIfEmpty(timer, rowId, columnFamily, columnName, mutation);
    });
  }

  CompletableFuture<Boolean> setIfValue(Timer timer, ByteString rowId, String columnFamily, String columnName, String columnEquals, Mutation mutation) {
    return toFuture(client.checkAndMutateRowAsync(ConditionalRowMutation.create(tableId, rowId)
                                                        .condition(FILTERS.chain()
                                                                          .filter(FILTERS.family().exactMatch(columnFamily))
                                                                          .filter(FILTERS.qualifier().exactMatch(columnName))
                                                                          .filter(FILTERS.value().exactMatch(columnEquals)))
                                                                        .then(mutation)), timer);
  }

  CompletableFuture<Boolean> setIfEmpty(Timer timer, ByteString rowId, String columnFamily, String columnName, Mutation mutation) {
    return toFuture(client.checkAndMutateRowAsync(ConditionalRowMutation.create(tableId, rowId)
                                                                        .condition(FILTERS.chain()
                                                                                          .filter(FILTERS.family().exactMatch(columnFamily))
                                                                                          .filter(FILTERS.qualifier().exactMatch(columnName))
                                                                                          .filter(FILTERS.value().regex("\\C+")))
                                                                        .otherwise(mutation)), timer)
        .thenApply(result -> !result);
  }


  static <T> CompletableFuture<T> toFuture(ApiFuture<T> future, Timer timer) {
    Timer.Context        timerContext = timer.time();
    CompletableFuture<T> result       = new CompletableFuture<>();

    ApiFutures.addCallback(future, new ApiFutureCallback<T>() {
      @Override
      public void onFailure(Throwable t) {
        timerContext.close();
        result.completeExceptionally(t);
      }

      @Override
      public void onSuccess(T t) {
        timerContext.close();
        result.complete(t);
      }
    }, MoreExecutors.directExecutor());

    return result;
  }

}
