/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.storage;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.google.api.core.ApiFutures;
import com.google.api.gax.rpc.ServerStream;
import com.google.cloud.bigtable.admin.v2.BigtableTableAdminClient;
import com.google.cloud.bigtable.admin.v2.BigtableTableAdminSettings;
import com.google.cloud.bigtable.admin.v2.models.CreateTableRequest;
import com.google.cloud.bigtable.data.v2.BigtableDataClient;
import com.google.cloud.bigtable.data.v2.BigtableDataSettings;
import com.google.cloud.bigtable.data.v2.models.BulkMutation;
import com.google.cloud.bigtable.data.v2.models.Mutation;
import com.google.cloud.bigtable.data.v2.models.Query;
import com.google.cloud.bigtable.data.v2.models.Row;
import com.google.cloud.bigtable.data.v2.models.RowCell;
import com.google.cloud.bigtable.data.v2.models.RowMutation;
import com.google.cloud.bigtable.data.v2.models.TableId;
import com.google.protobuf.ByteString;
import java.io.IOException;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.signal.storageservice.auth.User;
import org.signal.storageservice.storage.protos.contacts.StorageItem;
import org.signal.storageservice.storage.protos.contacts.StorageManifest;

class StorageManagerTest {

  private static final String CONTACTS_TABLE_NAME = "test-table";
  private static final TableId CONTACTS_TABLE_ID = TableId.of(CONTACTS_TABLE_NAME);

  private static final String MANIFESTS_TABLE_NAME = "manifest-table";
  private static final TableId MANIFESTS_TABLE_ID = TableId.of(MANIFESTS_TABLE_NAME);

  @RegisterExtension
  public final BigtableEmulatorExtension bigtableEmulator = BigtableEmulatorExtension.create();

  private BigtableDataClient client;

  @BeforeEach
  void setup() throws IOException {
    BigtableTableAdminSettings.Builder tableAdminSettings =
        BigtableTableAdminSettings.newBuilderForEmulator(bigtableEmulator.getPort())
            .setProjectId("foo")
            .setInstanceId("bar");

    try (BigtableTableAdminClient tableAdminClient = BigtableTableAdminClient.create(tableAdminSettings.build())) {

      tableAdminClient.createTable(CreateTableRequest.of(CONTACTS_TABLE_NAME).addFamily(StorageItemsTable.FAMILY));
      tableAdminClient.createTable(CreateTableRequest.of(MANIFESTS_TABLE_NAME).addFamily(StorageManifestsTable.FAMILY));

      BigtableDataSettings.Builder dataSettings = BigtableDataSettings.newBuilderForEmulator(bigtableEmulator.getPort())
          .setProjectId("foo")
          .setInstanceId("bar");

      client = BigtableDataClient.create(dataSettings.build());
    }
  }

  @AfterEach
  void tearDown() {
    client.close();
  }

  @Test
  void testReadManifest() throws ExecutionException, InterruptedException {
    UUID userId = UUID.randomUUID();
    User user = new User(userId);
    StorageManager contactsManager = new StorageManager(client, MANIFESTS_TABLE_NAME, CONTACTS_TABLE_NAME);

    client.mutateRow(RowMutation.create(MANIFESTS_TABLE_ID, userId + "#manifest",
        Mutation.create()
            .setCell(StorageManifestsTable.FAMILY, StorageManifestsTable.COLUMN_VERSION, "1")
            .setCell(StorageManifestsTable.FAMILY, StorageManifestsTable.COLUMN_DATA, "A manifest")));

    Optional<StorageManifest> manifest = contactsManager.getManifest(user).get();
    assertTrue(manifest.isPresent());
    assertThat(manifest.get().getVersion()).isEqualTo(1);
    assertThat(manifest.get().getValue().toStringUtf8()).isEqualTo("A manifest");
  }

  @Test
  void testGetManifestIfNotVersionDifferent() throws Exception {
    UUID userId = UUID.randomUUID();
    User user = new User(userId);
    StorageManager contactsManager = new StorageManager(client, MANIFESTS_TABLE_NAME, CONTACTS_TABLE_NAME);

    client.mutateRow(RowMutation.create(MANIFESTS_TABLE_ID, UUID.randomUUID() + "#manifest",
        Mutation.create()
            .setCell(StorageManifestsTable.FAMILY, StorageManifestsTable.COLUMN_VERSION, "4")
            .setCell(StorageManifestsTable.FAMILY, StorageManifestsTable.COLUMN_DATA, "A manifest other")));

    client.mutateRow(RowMutation.create(MANIFESTS_TABLE_ID, userId + "#manifest",
        Mutation.create()
            .setCell(StorageManifestsTable.FAMILY, StorageManifestsTable.COLUMN_VERSION, "3")
            .setCell(StorageManifestsTable.FAMILY, StorageManifestsTable.COLUMN_DATA, "A manifest")));

    Optional<StorageManifest> manifest = contactsManager.getManifestIfNotVersion(user, 2).get();
    assertTrue(manifest.isPresent());
    assertThat(manifest.get().getVersion()).isEqualTo(3);
    assertThat(manifest.get().getValue().toStringUtf8()).isEqualTo("A manifest");
  }

  @Test
  void testGetManifestIfNotVersionSame() throws Exception {
    UUID userId = UUID.randomUUID();
    User user = new User(userId);
    StorageManager contactsManager = new StorageManager(client, MANIFESTS_TABLE_NAME, CONTACTS_TABLE_NAME);

    client.mutateRow(RowMutation.create(MANIFESTS_TABLE_ID, UUID.randomUUID() + "#manifest",
        Mutation.create()
            .setCell(StorageManifestsTable.FAMILY, StorageManifestsTable.COLUMN_VERSION, "4")
            .setCell(StorageManifestsTable.FAMILY, StorageManifestsTable.COLUMN_DATA, "A manifest other")));

    client.mutateRow(RowMutation.create(MANIFESTS_TABLE_ID, userId + "#manifest",
        Mutation.create()
            .setCell(StorageManifestsTable.FAMILY, StorageManifestsTable.COLUMN_VERSION, "3")
            .setCell(StorageManifestsTable.FAMILY, StorageManifestsTable.COLUMN_DATA, "A manifest")));

    Optional<StorageManifest> manifest = contactsManager.getManifestIfNotVersion(user, 3).get();
    assertTrue(manifest.isEmpty());
  }

  @Test
  void testReadError() {
    BigtableDataClient client = mock(BigtableDataClient.class);
    when(client.readRowAsync(any(TableId.class), any(ByteString.class))).thenReturn(
        ApiFutures.immediateFailedFuture(new RuntimeException("Bad news")));

    UUID userId = UUID.randomUUID();
    User user = new User(userId);
    StorageManager contactsManager = new StorageManager(client, MANIFESTS_TABLE_NAME, CONTACTS_TABLE_NAME);

    assertThatThrownBy(() -> contactsManager.getManifest(user).get())
        .isInstanceOf(ExecutionException.class)
        .hasRootCauseMessage("Bad news");
  }

  @Test
  void testSetEmptyManifest() throws Exception {
    UUID userId = UUID.randomUUID();
    User user = new User(userId);
    StorageManager contactsManager = new StorageManager(client, MANIFESTS_TABLE_NAME, CONTACTS_TABLE_NAME);

    StorageManifest manifest = StorageManifest.newBuilder()
        .setVersion(1)
        .setValue(ByteString.copyFromUtf8("A manifest"))
        .build();

    StorageItem contact = StorageItem.newBuilder()
        .setKey(ByteString.copyFromUtf8("mykey"))
        .setValue(ByteString.copyFromUtf8("myvalue"))
        .build();

    Optional<StorageManifest> result = contactsManager.set(user, manifest, List.of(contact), new LinkedList<>()).get();

    assertTrue(result.isEmpty());

    Optional<StorageManifest> retrieved = contactsManager.getManifest(user).get();

    assertTrue(retrieved.isPresent());
    assertThat(retrieved.get().getVersion()).isEqualTo(1);
    assertThat(retrieved.get().getValue().toStringUtf8()).isEqualTo("A manifest");

    List<StorageItem> contacts = contactsManager.getItems(user, List.of(ByteString.copyFromUtf8("mykey"))).get();

    assertThat(contacts.size()).isEqualTo(1);
    assertThat(contacts.getFirst().getKey().toStringUtf8()).isEqualTo("mykey");
    assertThat(contacts.getFirst().getValue().toStringUtf8()).isEqualTo("myvalue");
  }

  @Test
  void testSetStaleManifest() throws Exception {
    UUID userId = UUID.randomUUID();
    User user = new User(userId);
    StorageManager contactsManager = new StorageManager(client, MANIFESTS_TABLE_NAME, CONTACTS_TABLE_NAME);

    StorageManifest manifest = StorageManifest.newBuilder()
        .setVersion(1)
        .setValue(ByteString.copyFromUtf8("A manifest"))
        .build();

    StorageManifest staleManifest = StorageManifest.newBuilder()
        .setVersion(1)
        .setValue(ByteString.copyFromUtf8("A stale value"))
        .build();

    StorageItem contact = StorageItem.newBuilder()
        .setKey(ByteString.copyFromUtf8("mykey"))
        .setValue(ByteString.copyFromUtf8("myvalue"))
        .build();

    StorageItem staleContact = StorageItem.newBuilder()
        .setKey(ByteString.copyFromUtf8("stalekey"))
        .setValue(ByteString.copyFromUtf8("stalevalue"))
        .build();

    Optional<StorageManifest> initialInsert = contactsManager.set(user, manifest, List.of(contact), new LinkedList<>())
        .get();
    assertTrue(initialInsert.isEmpty());

    Optional<StorageManifest> staleInsert = contactsManager.set(user, staleManifest, List.of(staleContact),
        List.of(ByteString.copyFromUtf8("mykey"))).get();
    assertTrue(staleInsert.isPresent());
    assertThat(staleInsert.get().getValue().toStringUtf8()).isEqualTo("A manifest");
    assertThat(staleInsert.get().getVersion()).isEqualTo(1);

    Optional<StorageManifest> retrieved = contactsManager.getManifest(user).get();

    assertTrue(retrieved.isPresent());
    assertThat(retrieved.get().getVersion()).isEqualTo(1);
    assertThat(retrieved.get().getValue().toStringUtf8()).isEqualTo("A manifest");

    List<StorageItem> contacts = contactsManager.getItems(user,
        List.of(ByteString.copyFromUtf8("mykey"), ByteString.copyFromUtf8("stalekey"))).get();

    assertThat(contacts.size()).isEqualTo(1);
    assertThat(contacts.getFirst().getKey().toStringUtf8()).isEqualTo("mykey");
    assertThat(contacts.getFirst().getValue().toStringUtf8()).isEqualTo("myvalue");
  }

  @Test
  void testSetUpdatedManifest() throws Exception {
    UUID userId = UUID.randomUUID();
    User user = new User(userId);
    StorageManager contactsManager = new StorageManager(client, MANIFESTS_TABLE_NAME, CONTACTS_TABLE_NAME);

    StorageManifest manifest = StorageManifest.newBuilder()
        .setVersion(1)
        .setValue(ByteString.copyFromUtf8("A manifest"))
        .build();

    StorageManifest updatedManifest = StorageManifest.newBuilder()
        .setVersion(2)
        .setValue(ByteString.copyFromUtf8("An updated manifest"))
        .build();

    StorageItem contact = StorageItem.newBuilder()
        .setKey(ByteString.copyFromUtf8("mykey"))
        .setValue(ByteString.copyFromUtf8("myvalue"))
        .build();

    StorageItem updatedContact = StorageItem.newBuilder()
        .setKey(ByteString.copyFromUtf8("updatedkey"))
        .setValue(ByteString.copyFromUtf8("updatedvalue"))
        .build();

    Optional<StorageManifest> initialInsert = contactsManager.set(user, manifest, List.of(contact), new LinkedList<>())
        .get();
    assertTrue(initialInsert.isEmpty());

    Optional<StorageManifest> updatedInsert = contactsManager.set(user, updatedManifest, List.of(updatedContact),
        List.of(ByteString.copyFromUtf8("mykey"))).get();
    assertTrue(updatedInsert.isEmpty());

    Optional<StorageManifest> retrieved = contactsManager.getManifest(user).get();

    assertTrue(retrieved.isPresent());
    assertThat(retrieved.get().getVersion()).isEqualTo(2);
    assertThat(retrieved.get().getValue().toStringUtf8()).isEqualTo("An updated manifest");

    List<StorageItem> contacts = contactsManager.getItems(user,
        List.of(ByteString.copyFromUtf8("mykey"), ByteString.copyFromUtf8("updatedkey"))).get();

    assertThat(contacts.size()).isEqualTo(1);
    assertThat(contacts.getFirst().getKey().toStringUtf8()).isEqualTo("updatedkey");
    assertThat(contacts.getFirst().getValue().toStringUtf8()).isEqualTo("updatedvalue");
  }

  @Test
  void testSetNoMutations() {
    final User user = new User(UUID.randomUUID());
    final StorageManager contactsManager = new StorageManager(client, MANIFESTS_TABLE_NAME, CONTACTS_TABLE_NAME);

    final StorageManifest manifest = StorageManifest.newBuilder()
        .setVersion(1)
        .setValue(ByteString.copyFromUtf8("A manifest"))
        .build();

    assertTrue(contactsManager.set(user, manifest, Collections.emptyList(), Collections.emptyList()).join().isEmpty());
    assertEquals(Optional.of(manifest), contactsManager.getManifest(user).join());
  }

  @Test
  void testClearItems() throws ExecutionException, InterruptedException {
    UUID userId = UUID.randomUUID();
    User user = new User(userId);

    UUID secondUserId = UUID.randomUUID();

    StorageManager contactsManager = new StorageManager(client, MANIFESTS_TABLE_NAME, CONTACTS_TABLE_NAME);

    for (int i = 0; i < 100; i++) {
      client.mutateRow(
          RowMutation.create(CONTACTS_TABLE_ID, userId + "#contact#somekey" + String.format("%03d", i),
              Mutation.create()
                  .setCell(StorageItemsTable.FAMILY, StorageItemsTable.COLUMN_DATA, "data" + String.format("%03d", i))
                  .setCell(StorageItemsTable.FAMILY, StorageItemsTable.COLUMN_KEY,
                      "somekey" + String.format("%03d", i))));
    }

    for (int i = 0; i < 100; i++) {
      client.mutateRow(
          RowMutation.create(CONTACTS_TABLE_ID, secondUserId + "#contact#somekey" + String.format("%03d", i),
              Mutation.create()
                  .setCell(StorageItemsTable.FAMILY, StorageItemsTable.COLUMN_DATA,
                      "seconddata" + String.format("%03d", i))
                  .setCell(StorageItemsTable.FAMILY, StorageItemsTable.COLUMN_KEY,
                      "somekey" + String.format("%03d", i))));
    }

    ServerStream<Row> rows = client.readRows(Query.create(CONTACTS_TABLE_ID).prefix(userId + "#contact#"));
    int i = 0;

    for (Row row : rows) {
      List<RowCell> cells = row.getCells(StorageItemsTable.FAMILY, StorageItemsTable.COLUMN_DATA);
      assertThat(cells.size()).isEqualTo(1);
      assertThat(cells.getFirst().getValue().toStringUtf8()).isEqualTo("data" + String.format("%03d", i));
      i++;
    }

    assertThat(i).isEqualTo(100);

    rows = client.readRows(Query.create(CONTACTS_TABLE_ID).prefix(secondUserId + "#contact#"));
    i = 0;

    for (Row row : rows) {
      List<RowCell> cells = row.getCells(StorageItemsTable.FAMILY, StorageItemsTable.COLUMN_DATA);
      assertThat(cells.size()).isEqualTo(1);
      assertThat(cells.getFirst().getValue().toStringUtf8()).isEqualTo("seconddata" + String.format("%03d", i));
      i++;
    }

    assertThat(i).isEqualTo(100);

    contactsManager.clearItems(user).get();

    rows = client.readRows(Query.create(CONTACTS_TABLE_ID).prefix(userId + "#contact#"));
    i = 0;

    for (Row ignored : rows) {
      i++;
    }

    assertThat(i).isEqualTo(0);

    rows = client.readRows(Query.create(CONTACTS_TABLE_ID).prefix(secondUserId + "#contact#"));
    i = 0;

    for (Row row : rows) {
      List<RowCell> cells = row.getCells(StorageItemsTable.FAMILY, StorageItemsTable.COLUMN_DATA);
      assertThat(cells.size()).isEqualTo(1);
      assertThat(cells.getFirst().getValue().toStringUtf8()).isEqualTo("seconddata" + String.format("%03d", i));
      i++;
    }

    assertThat(i).isEqualTo(100);
  }

  @Test
  void testClearItemsLargeBatch() {
    UUID userId = UUID.randomUUID();
    User user = new User(userId);

    StorageManager contactsManager = new StorageManager(client, MANIFESTS_TABLE_NAME, CONTACTS_TABLE_NAME);

    for (int chunk = 0; chunk < 2; chunk++) {
      final BulkMutation bulkMutation = BulkMutation.create(CONTACTS_TABLE_ID);

      // Each setCell() is a mutation
      final int setCellCallsPerLoop = 2;
      for (int i = 0; i < StorageItemsTable.MAX_MUTATIONS; i += setCellCallsPerLoop) {
        bulkMutation.add(String.format("%s#contact#somekey%d_%05d", userId, chunk, i),
            Mutation.create()
                .setCell(StorageItemsTable.FAMILY, StorageItemsTable.COLUMN_DATA, "data" + String.format("%03d", i))
                .setCell(StorageItemsTable.FAMILY, StorageItemsTable.COLUMN_KEY, "somekey" + String.format("%03d", i)));
      }

      client.bulkMutateRows(bulkMutation);
    }

    assertDoesNotThrow(() -> contactsManager.clearItems(user).join());

    int remainingRows = 0;

    for (final Row ignored : client.readRows(Query.create(CONTACTS_TABLE_ID).prefix(userId + "#contact#"))) {
      remainingRows++;
    }

    assertEquals(0, remainingRows);
  }

  @Test
  void testDelete() {
    UUID userId = UUID.randomUUID();
    User user = new User(userId);

    UUID secondUserId = UUID.randomUUID();
    User secondUser = new User(secondUserId);

    StorageManager contactsManager = new StorageManager(client, MANIFESTS_TABLE_NAME, CONTACTS_TABLE_NAME);

    client.mutateRow(RowMutation.create(MANIFESTS_TABLE_ID, userId + "#manifest",
        Mutation.create()
            .setCell(StorageManifestsTable.FAMILY, StorageManifestsTable.COLUMN_VERSION, "1")
            .setCell(StorageManifestsTable.FAMILY, StorageManifestsTable.COLUMN_DATA, "A manifest")));

    client.mutateRow(RowMutation.create(MANIFESTS_TABLE_ID, secondUserId + "#manifest",
        Mutation.create()
            .setCell(StorageManifestsTable.FAMILY, StorageManifestsTable.COLUMN_VERSION, "1")
            .setCell(StorageManifestsTable.FAMILY, StorageManifestsTable.COLUMN_DATA, "A different manifest")));

    for (int i = 0; i < 100; i++) {
      client.mutateRow(
          RowMutation.create(CONTACTS_TABLE_ID, userId + "#contact#somekey" + String.format("%03d", i),
              Mutation.create()
                  .setCell(StorageItemsTable.FAMILY, StorageItemsTable.COLUMN_DATA, "data" + String.format("%03d", i))
                  .setCell(StorageItemsTable.FAMILY, StorageItemsTable.COLUMN_KEY,
                      "somekey" + String.format("%03d", i))));
    }

    for (int i = 0; i < 100; i++) {
      client.mutateRow(
          RowMutation.create(CONTACTS_TABLE_ID, secondUserId + "#contact#somekey" + String.format("%03d", i),
              Mutation.create()
                  .setCell(StorageItemsTable.FAMILY, StorageItemsTable.COLUMN_DATA,
                      "seconddata" + String.format("%03d", i))
                  .setCell(StorageItemsTable.FAMILY, StorageItemsTable.COLUMN_KEY,
                      "somekey" + String.format("%03d", i))));
    }

    ServerStream<Row> rows = client.readRows(Query.create(CONTACTS_TABLE_ID).prefix(userId + "#contact#"));
    int i = 0;

    for (Row row : rows) {
      List<RowCell> cells = row.getCells(StorageItemsTable.FAMILY, StorageItemsTable.COLUMN_DATA);
      assertThat(cells.size()).isEqualTo(1);
      assertThat(cells.getFirst().getValue().toStringUtf8()).isEqualTo("data" + String.format("%03d", i));
      i++;
    }

    assertThat(i).isEqualTo(100);

    rows = client.readRows(Query.create(CONTACTS_TABLE_ID).prefix(secondUserId + "#contact#"));
    i = 0;

    for (Row row : rows) {
      List<RowCell> cells = row.getCells(StorageItemsTable.FAMILY, StorageItemsTable.COLUMN_DATA);
      assertThat(cells.size()).isEqualTo(1);
      assertThat(cells.getFirst().getValue().toStringUtf8()).isEqualTo("seconddata" + String.format("%03d", i));
      i++;
    }

    assertThat(i).isEqualTo(100);

    contactsManager.delete(user).join();

    rows = client.readRows(Query.create(CONTACTS_TABLE_ID).prefix(userId + "#contact#"));
    i = 0;

    for (Row ignored : rows) {
      i++;
    }

    assertThat(i).isEqualTo(0);

    rows = client.readRows(Query.create(CONTACTS_TABLE_ID).prefix(secondUserId + "#contact#"));
    i = 0;

    for (Row row : rows) {
      List<RowCell> cells = row.getCells(StorageItemsTable.FAMILY, StorageItemsTable.COLUMN_DATA);
      assertThat(cells.size()).isEqualTo(1);
      assertThat(cells.getFirst().getValue().toStringUtf8()).isEqualTo("seconddata" + String.format("%03d", i));
      i++;
    }

    assertThat(i).isEqualTo(100);

    assertFalse(contactsManager.getManifest(user).join().isPresent());

    Optional<StorageManifest> manifest = contactsManager.getManifest(secondUser).join();
    assertTrue(manifest.isPresent());
    assertThat(manifest.get().getVersion()).isEqualTo(1);
    assertThat(manifest.get().getValue().toStringUtf8()).isEqualTo("A different manifest");
  }

}
