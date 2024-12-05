/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.storage;

import com.google.protobuf.ByteString;
import org.signal.storageservice.auth.User;
import org.signal.storageservice.storage.bigtable.StorageManifestsTable;
import org.signal.storageservice.storage.protos.contacts.StorageItem;
import org.signal.storageservice.storage.protos.contacts.StorageManifest;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

public interface StorageManager {
    /**
   * Updates a manifest and applies mutations to stored items.
   *
   * @param user the user for whom to update manifests and mutate stored items
   * @param manifest the new manifest to store
   * @param inserts a list of new items to store
   * @param deletes a list of item identifiers to delete
   *
   * @return a future that completes when all updates and mutations have been applied; the future yields an empty value
   * if all updates and mutations were applied successfully, or the latest stored version of the {@code StorageManifest}
   * if the given {@code manifest}'s version is not exactly one version ahead of the stored manifest
   *
   * @see StorageManifestsTable#set(User, StorageManifest)
   */
  CompletableFuture<Optional<StorageManifest>> set(User user, StorageManifest manifest, List<StorageItem> inserts, List<ByteString> deletes);

  CompletableFuture<Optional<StorageManifest>> getManifest(User user) ;

  CompletableFuture<Optional<StorageManifest>> getManifestIfNotVersion(User user, long version);

  CompletableFuture<List<StorageItem>> getItems(User user, List<ByteString> keys);

  CompletableFuture<Void> clearItems(User user);

  CompletableFuture<Void> delete(User user);
}
