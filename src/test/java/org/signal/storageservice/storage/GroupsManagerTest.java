/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.storage;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.google.api.core.ApiFutures;
import com.google.cloud.bigtable.admin.v2.BigtableTableAdminClient;
import com.google.cloud.bigtable.admin.v2.BigtableTableAdminSettings;
import com.google.cloud.bigtable.admin.v2.models.CreateTableRequest;
import com.google.cloud.bigtable.data.v2.BigtableDataClient;
import com.google.cloud.bigtable.data.v2.BigtableDataSettings;
import com.google.cloud.bigtable.data.v2.models.Row;
import com.google.cloud.bigtable.data.v2.models.RowCell;
import com.google.cloud.bigtable.data.v2.models.TableId;
import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.signal.libsignal.zkgroup.groups.GroupPublicParams;
import org.signal.libsignal.zkgroup.groups.GroupSecretParams;
import org.signal.storageservice.storage.protos.groups.AccessControl;
import org.signal.storageservice.storage.protos.groups.Group;
import org.signal.storageservice.storage.protos.groups.GroupChange;
import org.signal.storageservice.storage.protos.groups.GroupChange.Actions;
import org.signal.storageservice.storage.protos.groups.GroupChange.Actions.ModifyTitleAction;
import org.signal.storageservice.storage.protos.groups.GroupChanges.GroupChangeState;
import org.signal.storageservice.util.AuthHelper;
import org.signal.storageservice.util.Conversions;

class GroupsManagerTest {

  private static final String GROUPS_TABLE_NAME = "groups-table";
  private static final TableId GROUPS_TABLE_ID = TableId.of(GROUPS_TABLE_NAME);

  private static final String GROUP_LOGS_TABLE_NAME = "group-logs-table";
  private static final TableId GROUP_LOGS_TABLE_ID = TableId.of(GROUP_LOGS_TABLE_NAME);

  @RegisterExtension
  private final BigtableEmulatorExtension bigtableEmulator = BigtableEmulatorExtension.create();

  private BigtableDataClient client;

  @BeforeEach
  void setup() throws IOException {
    BigtableTableAdminSettings.Builder tableAdminSettings = BigtableTableAdminSettings.newBuilderForEmulator(bigtableEmulator.getPort()).setProjectId("foo").setInstanceId("bar");
    try (BigtableTableAdminClient tableAdminClient = BigtableTableAdminClient.create(tableAdminSettings.build())) {

      BigtableDataSettings.Builder dataSettings = BigtableDataSettings.newBuilderForEmulator(bigtableEmulator.getPort())
          .setProjectId("foo").setInstanceId("bar");
      client = BigtableDataClient.create(dataSettings.build());

      tableAdminClient.createTable(CreateTableRequest.of(GROUPS_TABLE_NAME).addFamily(GroupsTable.FAMILY));
      tableAdminClient.createTable(CreateTableRequest.of(GROUP_LOGS_TABLE_NAME).addFamily(GroupLogTable.FAMILY));
    }
  }

  @AfterEach
  void teardown() {
    client.close();
  }

  @Test
  void testCreateGroup() throws Exception {
    GroupsManager groupsManager = new GroupsManager(client, GROUPS_TABLE_NAME, GROUP_LOGS_TABLE_NAME);

    GroupSecretParams groupSecretParams = GroupSecretParams.generate();
    GroupPublicParams groupPublicParams = groupSecretParams.getPublicParams();
    ByteString        groupId           = ByteString.copyFrom(groupPublicParams.getGroupIdentifier().serialize());

    Group group = Group.newBuilder()
                       .setVersion(0)
                       .setTitle(ByteString.copyFromUtf8("Some title"))
                       .setAvatar("Some avatar")
                       .setAccessControl(AccessControl.newBuilder()
                                                      .setMembers(AccessControl.AccessRequired.MEMBER)
                                                      .setAttributes(AccessControl.AccessRequired.MEMBER))
                       .setPublicKey(ByteString.copyFrom(groupPublicParams.serialize()))
                       .build();

    CompletableFuture<Boolean> result = groupsManager.createGroup(groupId, group);
    assertTrue(result.get());

    Row row = client.readRow(GROUPS_TABLE_ID, groupId);
    List<RowCell> versionCells= row.getCells(GroupsTable.FAMILY, GroupsTable.COLUMN_VERSION);

    assertThat(versionCells.size()).isEqualTo(1);
    assertThat(versionCells.getFirst().getValue().toStringUtf8()).isEqualTo("0");

    List<RowCell> dataCells = row.getCells(GroupsTable.FAMILY, GroupsTable.COLUMN_GROUP_DATA);

    assertThat(dataCells.size()).isEqualTo(1);
    assertThat(Group.parseFrom(dataCells.getFirst().getValue())).isEqualTo(group);
  }

  @Test
  void testCreateGroupConflict() throws Exception {
    GroupsManager groupsManager = new GroupsManager(client, GROUPS_TABLE_NAME, GROUP_LOGS_TABLE_NAME);

    GroupSecretParams groupSecretParams = GroupSecretParams.generate();
    GroupPublicParams groupPublicParams = groupSecretParams.getPublicParams();
    ByteString        groupId           = ByteString.copyFrom(groupPublicParams.getGroupIdentifier().serialize());

    Group group = Group.newBuilder()
                       .setVersion(0)
                       .setTitle(ByteString.copyFromUtf8("Some title"))
                       .setAvatar("Some avatar")
                       .setAccessControl(AccessControl.newBuilder()
                                                      .setMembers(AccessControl.AccessRequired.MEMBER)
                                                      .setAttributes(AccessControl.AccessRequired.MEMBER))
                       .setPublicKey(ByteString.copyFrom(groupPublicParams.serialize()))
                       .build();

    CompletableFuture<Boolean> result = groupsManager.createGroup(groupId, group);
    assertTrue(result.get());

    Group conflictingGroup = Group.newBuilder()
                                  .setVersion(0)
                                  .setTitle(ByteString.copyFromUtf8("Another title"))
                                  .setAvatar("Another avatar")
                                  .setAccessControl(AccessControl.newBuilder()
                                                                 .setMembers(AccessControl.AccessRequired.MEMBER)
                                                                 .setAttributes(AccessControl.AccessRequired.MEMBER))
                                  .setPublicKey(ByteString.copyFrom(groupPublicParams.serialize()))
                                  .build();

    CompletableFuture<Boolean> conflicting = groupsManager.createGroup(groupId, group);
    assertFalse(conflicting.get());

    Row row = client.readRow(GROUPS_TABLE_ID, groupId);
    List<RowCell> versionCells= row.getCells(GroupsTable.FAMILY, GroupsTable.COLUMN_VERSION);

    assertThat(versionCells.size()).isEqualTo(1);
    assertThat(versionCells.getFirst().getValue().toStringUtf8()).isEqualTo("0");

    List<RowCell> dataCells = row.getCells(GroupsTable.FAMILY, GroupsTable.COLUMN_GROUP_DATA);

    assertThat(dataCells.size()).isEqualTo(1);
    assertThat(Group.parseFrom(dataCells.getFirst().getValue())).isEqualTo(group);
    assertThat(Group.parseFrom(dataCells.getFirst().getValue())).isNotEqualTo(conflictingGroup);
  }

  @Test
  void testUpdateGroup() throws Exception {
    GroupsManager groupsManager = new GroupsManager(client, GROUPS_TABLE_NAME, GROUP_LOGS_TABLE_NAME);

    GroupSecretParams groupSecretParams = GroupSecretParams.generate();
    GroupPublicParams groupPublicParams = groupSecretParams.getPublicParams();
    ByteString        groupId           = ByteString.copyFrom(groupPublicParams.getGroupIdentifier().serialize());

    Group group = Group.newBuilder()
                       .setVersion(0)
                       .setTitle(ByteString.copyFromUtf8("Some title"))
                       .setAvatar("Some avatar")
                       .setAccessControl(AccessControl.newBuilder()
                                                      .setMembers(AccessControl.AccessRequired.MEMBER)
                                                      .setAttributes(AccessControl.AccessRequired.MEMBER))
                       .setPublicKey(ByteString.copyFrom(groupPublicParams.serialize()))
                       .build();

    CompletableFuture<Boolean> result = groupsManager.createGroup(groupId, group);
    assertTrue(result.get());

    Group updated = group.toBuilder()
                         .setVersion(1)
                         .setTitle(ByteString.copyFromUtf8("Updated title"))
                         .build();

    CompletableFuture<Optional<Group>> update = groupsManager.updateGroup(groupId, updated);
    assertThat(update.get()).isEmpty();

    Row row = client.readRow(GROUPS_TABLE_ID, groupId);
    List<RowCell> versionCells= row.getCells(GroupsTable.FAMILY, GroupsTable.COLUMN_VERSION);

    assertThat(versionCells.size()).isEqualTo(1);
    assertThat(versionCells.getFirst().getValue().toStringUtf8()).isEqualTo("1");

    List<RowCell> dataCells = row.getCells(GroupsTable.FAMILY, GroupsTable.COLUMN_GROUP_DATA);

    assertThat(dataCells.size()).isEqualTo(1);
    assertThat(Group.parseFrom(dataCells.getFirst().getValue())).isEqualTo(updated);
    assertThat(Group.parseFrom(dataCells.getFirst().getValue())).isNotEqualTo(group);
  }

  @Test
  void testUpdateStaleGroup() throws Exception {
    GroupsManager groupsManager = new GroupsManager(client, GROUPS_TABLE_NAME, GROUP_LOGS_TABLE_NAME);

    GroupSecretParams groupSecretParams = GroupSecretParams.generate();
    GroupPublicParams groupPublicParams = groupSecretParams.getPublicParams();
    ByteString        groupId           = ByteString.copyFrom(groupPublicParams.getGroupIdentifier().serialize());

    Group group = Group.newBuilder()
                       .setVersion(0)
                       .setTitle(ByteString.copyFromUtf8("Some title"))
                       .setAvatar("Some avatar")
                       .setAccessControl(AccessControl.newBuilder()
                                                      .setMembers(AccessControl.AccessRequired.MEMBER)
                                                      .setAttributes(AccessControl.AccessRequired.MEMBER))
                       .setPublicKey(ByteString.copyFrom(groupPublicParams.serialize()))
                       .build();

    CompletableFuture<Boolean> result = groupsManager.createGroup(groupId, group);
    assertTrue(result.get());

    Group updated = group.toBuilder()
                         .setVersion(0)
                         .setTitle(ByteString.copyFromUtf8("Updated title"))
                         .build();

    CompletableFuture<Optional<Group>> update = groupsManager.updateGroup(groupId, updated);
    assertThat(update.get()).isPresent()
        .get().isEqualTo(group);

    Row row = client.readRow(GROUPS_TABLE_ID, groupId);
    List<RowCell> versionCells= row.getCells(GroupsTable.FAMILY, GroupsTable.COLUMN_VERSION);

    assertThat(versionCells.size()).isEqualTo(1);
    assertThat(versionCells.getFirst().getValue().toStringUtf8()).isEqualTo("0");

    List<RowCell> dataCells = row.getCells(GroupsTable.FAMILY, GroupsTable.COLUMN_GROUP_DATA);

    assertThat(dataCells.size()).isEqualTo(1);
    assertThat(Group.parseFrom(dataCells.getFirst().getValue())).isEqualTo(group);
    assertThat(Group.parseFrom(dataCells.getFirst().getValue())).isNotEqualTo(updated);
  }

  @Test
  void testGetGroup() throws Exception {
    GroupsManager groupsManager = new GroupsManager(client, GROUPS_TABLE_NAME, GROUP_LOGS_TABLE_NAME);

    GroupSecretParams groupSecretParams = GroupSecretParams.generate();
    GroupPublicParams groupPublicParams = groupSecretParams.getPublicParams();
    ByteString        groupId           = ByteString.copyFrom(groupPublicParams.getGroupIdentifier().serialize());

    Group group = Group.newBuilder()
                       .setVersion(0)
                       .setTitle(ByteString.copyFromUtf8("Some title"))
                       .setAvatar("Some avatar")
                       .setAccessControl(AccessControl.newBuilder()
                                                      .setMembers(AccessControl.AccessRequired.MEMBER)
                                                      .setAttributes(AccessControl.AccessRequired.MEMBER))
                       .setPublicKey(ByteString.copyFrom(groupPublicParams.serialize()))
                       .build();

    CompletableFuture<Boolean> result = groupsManager.createGroup(groupId, group);
    assertTrue(result.get());

    CompletableFuture<Optional<Group>> retrieved = groupsManager.getGroup(groupId);
    assertThat(retrieved.get().isPresent()).isTrue();
    assertThat(retrieved.get().get()).isEqualTo(group);
  }

  @Test
  void testGetGroupNotFound() throws Exception {
    GroupsManager groupsManager = new GroupsManager(client, GROUPS_TABLE_NAME, GROUP_LOGS_TABLE_NAME);

    GroupSecretParams groupSecretParams = GroupSecretParams.generate();
    GroupPublicParams groupPublicParams = groupSecretParams.getPublicParams();
    ByteString        groupId           = ByteString.copyFrom(groupPublicParams.getGroupIdentifier().serialize());

    Group group = Group.newBuilder()
                       .setVersion(0)
                       .setTitle(ByteString.copyFromUtf8("Some title"))
                       .setAvatar("Some avatar")
                       .setAccessControl(AccessControl.newBuilder()
                                                      .setMembers(AccessControl.AccessRequired.MEMBER)
                                                      .setAttributes(AccessControl.AccessRequired.MEMBER))
                       .setPublicKey(ByteString.copyFrom(groupPublicParams.serialize()))
                       .build();

    CompletableFuture<Boolean> result = groupsManager.createGroup(groupId, group);
    assertTrue(result.get());

    CompletableFuture<Optional<Group>> retrieved = groupsManager.getGroup(ByteString.copyFrom(GroupSecretParams.generate().getPublicParams().getGroupIdentifier().serialize()));
    assertThat(retrieved.get().isPresent()).isFalse();
    assertThat(retrieved.get().isEmpty()).isTrue();
  }


  @Test
  void testReadError() {
    BigtableDataClient client = mock(BigtableDataClient.class);
    when(client.readRowAsync(any(TableId.class), any(ByteString.class)))
        .thenReturn(ApiFutures.immediateFailedFuture(new RuntimeException("Bad news")));

    GroupsManager groupsManager = new GroupsManager(client, GROUPS_TABLE_NAME, GROUP_LOGS_TABLE_NAME);

    assertThatThrownBy(() -> groupsManager.getGroup(ByteString.copyFrom(new byte[16])).get())
        .isInstanceOf(ExecutionException.class)
        .hasRootCauseMessage("Bad news");
  }

  @Test
  void testAppendLog() throws ExecutionException, InterruptedException, InvalidProtocolBufferException {
    GroupsManager     groupsManager     = new GroupsManager(client, GROUPS_TABLE_NAME, GROUP_LOGS_TABLE_NAME);
    GroupSecretParams groupSecretParams = GroupSecretParams.generate();
    GroupPublicParams groupPublicParams = groupSecretParams.getPublicParams();
    ByteString        groupId           = ByteString.copyFrom(groupPublicParams.getGroupIdentifier().serialize());

    Actions actions = Actions.newBuilder()
                             .setModifyTitle(ModifyTitleAction.newBuilder()
                                                              .setTitle(ByteString.copyFromUtf8("Some new title")))
                             .build();

    GroupChange change = GroupChange.newBuilder()
                                    .setActions(actions.toByteString())
                                    .setServerSignature(ByteString.copyFrom(AuthHelper.GROUPS_SERVER_KEY.sign(actions.toByteArray()).serialize()))
                                    .build();

    Group groupState = Group.newBuilder()
                            .setTitle(ByteString.copyFromUtf8("Some new title"))
                            .setAvatar("some avatar")
                            .build();

    CompletableFuture<Boolean> insert = groupsManager.appendChangeRecord(groupId, 1, change, groupState);
    assertTrue(insert.get());

    Row row = client.readRow(GROUP_LOGS_TABLE_ID, groupId.concat(ByteString.copyFromUtf8("#")).concat(ByteString.copyFrom(Conversions.intToByteArray(1))));
    List<RowCell> versionCells = row.getCells(GroupLogTable.FAMILY, GroupLogTable.COLUMN_VERSION);

    assertThat(versionCells.size()).isEqualTo(1);
    assertThat(versionCells.getFirst().getValue().toStringUtf8()).isEqualTo("1");

    List<RowCell> dataCells = row.getCells(GroupLogTable.FAMILY, GroupLogTable.COLUMN_CHANGE);

    assertThat(dataCells.size()).isEqualTo(1);
    assertThat(GroupChange.parseFrom(dataCells.getFirst().getValue())).isEqualTo(change);

    List<RowCell> groupStateCells = row.getCells(GroupLogTable.FAMILY, GroupLogTable.COLUMN_STATE);

    assertThat(groupStateCells.size()).isEqualTo(1);
    assertThat(Group.parseFrom(groupStateCells.getFirst().getValue())).isEqualTo(groupState);
  }

  @Test
  void testQueryLog() throws ExecutionException, InterruptedException, InvalidProtocolBufferException {
    GroupsManager     groupsManager     = new GroupsManager(client, GROUPS_TABLE_NAME, GROUP_LOGS_TABLE_NAME);
    GroupSecretParams groupSecretParams = GroupSecretParams.generate();
    GroupPublicParams groupPublicParams = groupSecretParams.getPublicParams();
    ByteString        groupId           = ByteString.copyFrom(groupPublicParams.getGroupIdentifier().serialize());

    Group latestGroupState = null;
    for (int i=1;i<2000;i++) {
      Actions actions = Actions.newBuilder()
                               .setModifyTitle(ModifyTitleAction.newBuilder()
                                                                .setTitle(ByteString.copyFromUtf8("Some new title " + i)))
                               .build();

      GroupChange change = GroupChange.newBuilder()
                                      .setActions(actions.toByteString())
                                      .setServerSignature(ByteString.copyFrom(AuthHelper.GROUPS_SERVER_KEY.sign(actions.toByteArray()).serialize()))
                                      .setChangeEpoch(i%10)  // spread some change epoch versions throughout
                                      .build();

      Group groupState = Group.newBuilder()
                              .setTitle(ByteString.copyFromUtf8("Some new title " + i))
                              .setVersion(i)
                              .build();
      latestGroupState = groupState;

      CompletableFuture<Boolean> insert = groupsManager.appendChangeRecord(groupId, i, change, groupState);
      assertTrue(insert.get());
    }

    assertThat(latestGroupState).isNotNull();
    List<GroupChangeState> changes = groupsManager.getChangeRecords(groupId, latestGroupState, null, false, false, 1, 20).get();
    assertThat(changes.size()).isEqualTo(19);

    for (int i=1;i<20;i++) {
      assertThat(Actions.parseFrom(changes.get(i-1).getGroupChange().getActions()).getModifyTitle().getTitle().toStringUtf8()).isEqualTo("Some new title " + i);
      assertThat(changes.get(i-1).getGroupState().getTitle().toStringUtf8()).isEqualTo("Some new title " + i);
    }

    changes = groupsManager.getChangeRecords(groupId, latestGroupState, null, false, false, 10, 200).get();
    assertThat(changes.size()).isEqualTo(190);

    for (int i=10;i<200;i++) {
      assertThat(Actions.parseFrom(changes.get(i-10).getGroupChange().getActions()).getModifyTitle().getTitle().toStringUtf8()).isEqualTo("Some new title " + i);
      assertThat(changes.get(i-10).getGroupState().getTitle().toStringUtf8()).isEqualTo("Some new title " + i);
    }

    changes = groupsManager.getChangeRecords(groupId, latestGroupState, 5, false, false, 1, 20).get();
    assertThat(changes.size()).isEqualTo(19);
    for (int i=1;i<20;i++) {
      GroupChangeState change = changes.get(i - 1);
      assertThat(Actions.parseFrom(change.getGroupChange().getActions()).getModifyTitle().getTitle().toStringUtf8()).isEqualTo("Some new title " + i);
      if (i % 10 > 5) {
        assertThat(change.getGroupState().getTitle().toStringUtf8()).isEqualTo("Some new title " + i);
      } else {
        assertThat(change.hasGroupState()).as("change %d does not have group state set", i).isFalse();
      }
    }

    changes = groupsManager.getChangeRecords(groupId, latestGroupState, 5, true, true, 2, 5).get();
    assertThat(changes.size()).isEqualTo(3);
    for (int i=2;i<5;i++) {
      GroupChangeState change = changes.get(i - 2);
      assertThat(Actions.parseFrom(change.getGroupChange().getActions()).getModifyTitle().getTitle().toStringUtf8()).isEqualTo("Some new title " + i);
      if (i == 3) {
        assertThat(change.hasGroupState()).as("change %d does not have group state set since it is neither first nor last", i).isFalse();
      } else {
        assertThat(change.hasGroupState()).as("change %d has group state set since it is first or last", i).isTrue();
        assertThat(change.getGroupState().getTitle().toStringUtf8()).isEqualTo("Some new title " + i);
      }
    }
  }
}
