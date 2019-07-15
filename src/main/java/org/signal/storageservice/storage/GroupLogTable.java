/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.storage;

import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.SharedMetricRegistries;
import com.codahale.metrics.Timer;
import com.google.api.gax.rpc.ResponseObserver;
import com.google.api.gax.rpc.StreamController;
import com.google.cloud.bigtable.data.v2.BigtableDataClient;
import com.google.cloud.bigtable.data.v2.models.Mutation;
import com.google.cloud.bigtable.data.v2.models.Query;
import com.google.cloud.bigtable.data.v2.models.Row;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import org.signal.storageservice.metrics.StorageMetrics;
import org.signal.storageservice.storage.protos.groups.Group;
import org.signal.storageservice.storage.protos.groups.GroupChange;
import org.signal.storageservice.storage.protos.groups.GroupChanges.GroupChangeState;
import org.signal.storageservice.util.Conversions;

import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.CompletableFuture;

import static com.codahale.metrics.MetricRegistry.name;

public class GroupLogTable extends Table {

  public static final String FAMILY = "l";

  public static final String COLUMN_VERSION   = "v";
  public static final String COLUMN_CHANGE    = "c";
  public static final String COLUMN_STATE     = "s";

  private final MetricRegistry metricRegistry      = SharedMetricRegistries.getOrCreate(StorageMetrics.NAME);
  private final Timer          appendTimer         = metricRegistry.timer(name(GroupLogTable.class, "append"        ));
  private final Timer          getFromVersionTimer = metricRegistry.timer(name(GroupLogTable.class, "getFromVersion"));

  public GroupLogTable(BigtableDataClient client, String tableId) {
    super(client, tableId);
  }

  public CompletableFuture<Boolean> append(ByteString groupId, int version, GroupChange groupChange, Group group) {
    return setIfEmpty(appendTimer,
                      getRowId(groupId, version),
                      FAMILY, COLUMN_CHANGE,
                      Mutation.create()
                              .setCell(FAMILY, ByteString.copyFromUtf8(COLUMN_CHANGE), 0L, groupChange.toByteString())
                              .setCell(FAMILY, COLUMN_VERSION, 0, String.valueOf(version))
                              .setCell(FAMILY, ByteString.copyFromUtf8(COLUMN_STATE), 0L, group.toByteString()));
  }

  public CompletableFuture<List<GroupChangeState>> getRecordsFromVersion(ByteString groupId, int fromVersionInclusive, int toVersionExclusive) {

    Timer.Context                             timerContext = getFromVersionTimer.time();
    CompletableFuture<List<GroupChangeState>> future       = new CompletableFuture<>();
    Query                                     query        = Query.create(tableId);

    query.range(getRowId(groupId, fromVersionInclusive), getRowId(groupId, toVersionExclusive));

    client.readRowsAsync(query, new ResponseObserver<>() {
      List<GroupChangeState> results = new LinkedList<>();

      @Override
      public void onStart(StreamController controller) {}

      @Override
      public void onResponse(Row response) {
        try {
          results.add(GroupChangeState.newBuilder()
                                      .setGroupChange(GroupChange.parseFrom(response.getCells(FAMILY, COLUMN_CHANGE).stream().findFirst().orElseThrow().getValue()))
                                      .setGroupState(Group.parseFrom(response.getCells(FAMILY, COLUMN_STATE).stream().findFirst().orElseThrow().getValue()))
                                      .build());

        } catch (InvalidProtocolBufferException e) {
          future.completeExceptionally(e);
        }
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

  private ByteString getRowId(ByteString groupId, int version) {
    return groupId.concat(ByteString.copyFromUtf8("#")).concat(ByteString.copyFrom(Conversions.intToByteArray(version)));
  }

}
