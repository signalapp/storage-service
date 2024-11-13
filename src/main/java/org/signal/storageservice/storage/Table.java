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
import com.google.cloud.bigtable.data.v2.models.TableId;
import com.google.common.util.concurrent.MoreExecutors;
import com.google.protobuf.ByteString;

import java.util.concurrent.CompletableFuture;

import static com.google.cloud.bigtable.data.v2.models.Filters.FILTERS;

abstract class Table {

  final BigtableDataClient client;
  final TableId tableId;

  public Table(final BigtableDataClient client, final String tableId) {
    this.client = client;
    this.tableId = TableId.of(tableId);
  }

  /**
   * Applies a mutation to the given row if and only if the cell with the given column family/name has exactly the given
   * value <em>or</em> the identified cell is empty.
   *
   * @param timer a timer to measure the duration of the operation
   * @param rowId the ID of the row to potentially mutate
   * @param columnFamily the column family of the cell to check for a specific value
   * @param columnName the column name of the cell to check for a specific value
   * @param columnEquals the value for which to check in the identified cell
   * @param mutation the mutation to apply if {@code columnEquals} exactly matches the existing value in the identified
   *                 cell or if the identified cell is empty
   *
   * @return a future that yields {@code true} if the identified row was modified or {@code false} otherwise
   * */
  CompletableFuture<Boolean> setIfValueOrEmpty(Timer timer, ByteString rowId, String columnFamily, String columnName, String columnEquals, Mutation mutation) {
    return setIfValue(timer, rowId, columnFamily, columnName, columnEquals, mutation)
        .thenCompose(mutated -> mutated
            ? CompletableFuture.completedFuture(true)
            : setIfEmpty(timer, rowId, columnFamily, columnName, mutation));
  }

  /**
   * Applies a mutation to the given row if and only if the cell with the given column family/name has exactly the given
   * value.
   *
   * @param timer a timer to measure the duration of the operation
   * @param rowId the ID of the row to potentially mutate
   * @param columnFamily the column family of the cell to check for a specific value
   * @param columnName the column name of the cell to check for a specific value
   * @param columnEquals the value for which to check in the identified cell
   * @param mutation the mutation to apply if {@code columnEquals} exactly matches the existing value in the identified
   *                 cell
   *
   * @return a future that yields {@code true} if the identified row was modified or {@code false} otherwise
   */
  CompletableFuture<Boolean> setIfValue(Timer timer, ByteString rowId, String columnFamily, String columnName, String columnEquals, Mutation mutation) {
    return toFuture(client.checkAndMutateRowAsync(ConditionalRowMutation.create(tableId, rowId)
        .condition(FILTERS.chain()
            .filter(FILTERS.family().exactMatch(columnFamily))
            .filter(FILTERS.qualifier().exactMatch(columnName))
            .filter(FILTERS.value().exactMatch(columnEquals)))
        .then(mutation)), timer);
  }

  /**
   * Applies a mutation to the given row if and only if the cell with the given column family/name is empty.
   *
   * @param timer a timer to measure the duration of the operation
   * @param rowId the ID of the row to potentially mutate
   * @param columnFamily the column family of the cell to check for a specific value
   * @param columnName the column name of the cell to check for a specific value
   * @param mutation the mutation to apply if the identified cell is empty
   *
   * @return a future that yields {@code true} if the identified row was modified or {@code false} otherwise
   */
  CompletableFuture<Boolean> setIfEmpty(Timer timer, ByteString rowId, String columnFamily, String columnName, Mutation mutation) {
    return toFuture(client.checkAndMutateRowAsync(ConditionalRowMutation.create(tableId, rowId)
        .condition(FILTERS.chain()
            .filter(FILTERS.family().exactMatch(columnFamily))
            .filter(FILTERS.qualifier().exactMatch(columnName))
            // See https://github.com/google/re2/wiki/Syntax; `\C` is "any byte", and so this matches any
            // non-empty value. Note that the mutation is applied in an `otherwise` clause.
            .filter(FILTERS.value().regex("\\C+")))
        .otherwise(mutation)), timer)
        // Note that we apply the mutation only if the predicate does NOT match, and so we invert `predicateMatched` to
        // indicate that we have (or haven't) mutated the row
        .thenApply(predicateMatched -> !predicateMatched);
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
