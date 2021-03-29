/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.storage;

import com.google.cloud.bigtable.data.v2.BigtableDataClient;
import com.google.protobuf.ByteString;
import org.signal.storageservice.auth.User;
import org.signal.storageservice.storage.protos.contacts.StorageItem;
import org.signal.storageservice.storage.protos.contacts.StorageManifest;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

public class StorageManager {

  private final StorageManifestsTable manifestsTable;
  private final StorageItemsTable     itemsTable;

  public StorageManager(BigtableDataClient client, String contactManifestsTableId, String contactsTableId) {
    this.manifestsTable = new StorageManifestsTable(client, contactManifestsTableId);
    this.itemsTable     = new StorageItemsTable(client, contactsTableId);
  }

  public CompletableFuture<Optional<StorageManifest>> set(User user, StorageManifest manifest, List<StorageItem> inserts, List<ByteString> deletes) {
    return manifestsTable.set(user, manifest)
                         .thenCompose(updated -> {
                           if (updated) {
                             return itemsTable.set(user, inserts, deletes).thenApply(nothing -> Optional.empty());
                           } else {
                             return getManifest(user).thenApply(retrieved -> Optional.of(retrieved.orElseThrow()));
                           }
                         });
  }

  public CompletableFuture<Optional<StorageManifest>> getManifest(User user) {
    return manifestsTable.get(user);
  }

  public CompletableFuture<Optional<StorageManifest>> getManifestIfNotVersion(User user, long version) {
    return manifestsTable.getIfNotVersion(user, version);
  }

  public CompletableFuture<List<StorageItem>> getItems(User user, List<ByteString> keys) {
    return itemsTable.get(user, keys);
  }

  public CompletableFuture<Void> clearItems(User user) {
    return itemsTable.clear(user);
  }

  public CompletableFuture<Void> delete(User user) {
    return CompletableFuture.allOf(itemsTable.clear(user), manifestsTable.clear(user));
  }
}
