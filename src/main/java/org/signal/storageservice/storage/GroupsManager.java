/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.storage;

import com.google.cloud.bigtable.data.v2.BigtableDataClient;
import com.google.protobuf.ByteString;
import org.signal.storageservice.storage.protos.groups.Group;
import org.signal.storageservice.storage.protos.groups.GroupChange;
import org.signal.storageservice.storage.protos.groups.GroupChanges.GroupChangeState;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

public class GroupsManager {

  private final GroupsTable   groupsTable;
  private final GroupLogTable groupLogTable;

  public GroupsManager(BigtableDataClient client, String groupsTableId, String groupLogsTableId) {
    this.groupsTable   = new GroupsTable  (client, groupsTableId   );
    this.groupLogTable = new GroupLogTable(client, groupLogsTableId);
  }

  public CompletableFuture<Optional<Group>> getGroup(ByteString groupId) {
    return groupsTable.getGroup(groupId);
  }

  public CompletableFuture<Boolean> createGroup(ByteString groupId, Group group) {
    return groupsTable.createGroup(groupId, group);
  }

  public CompletableFuture<Optional<Group>> updateGroup(ByteString groupId, Group group) {
    return groupsTable.updateGroup(groupId, group)
                      .thenCompose(modified -> {
                        if (modified) return CompletableFuture.completedFuture(Optional.empty());
                        else          return getGroup(groupId).thenApply(result -> Optional.of(result.orElseThrow()));
                      });
  }

  public CompletableFuture<List<GroupChangeState>> getChangeRecords(ByteString groupId, int fromVersionInclusive, int toVersionExclusive) {
    return groupLogTable.getRecordsFromVersion(groupId, fromVersionInclusive, toVersionExclusive);
  }

  public CompletableFuture<Boolean> appendChangeRecord(ByteString groupId, int version, GroupChange change, Group state) {
    return groupLogTable.append(groupId, version, change, state);
  }


}
