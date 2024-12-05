/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.storage;

import com.google.protobuf.ByteString;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import org.signal.storageservice.storage.protos.groups.Group;
import org.signal.storageservice.storage.protos.groups.GroupChange;
import org.signal.storageservice.storage.protos.groups.GroupChanges.GroupChangeState;
import javax.annotation.Nullable;

public interface GroupsManager {

  CompletableFuture<Optional<Group>> getGroup(ByteString groupId);

  CompletableFuture<Boolean> createGroup(ByteString groupId, Group group);

  CompletableFuture<Optional<Group>> updateGroup(ByteString groupId, Group group);


  CompletableFuture<List<GroupChangeState>> getChangeRecords(ByteString groupId, Group group,
      @Nullable Integer maxSupportedChangeEpoch, boolean includeFirstState, boolean includeLastState,
      int fromVersionInclusive, int toVersionExclusive);

  CompletableFuture<Boolean> appendChangeRecord(ByteString groupId, int version, GroupChange change, Group state);
}
