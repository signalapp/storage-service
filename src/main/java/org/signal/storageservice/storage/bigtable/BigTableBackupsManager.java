/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.storage.bigtable;

import com.google.api.core.ApiFuture;
import com.google.api.core.ApiFutureCallback;
import com.google.api.core.ApiFutures;
import com.google.cloud.bigtable.admin.v2.BigtableTableAdminClient;
import com.google.cloud.bigtable.admin.v2.models.Backup;
import com.google.cloud.bigtable.admin.v2.models.CreateBackupRequest;
import com.google.common.util.concurrent.MoreExecutors;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;
import org.signal.storageservice.storage.BackupsManager;
import org.signal.storageservice.util.Pair;

public class BigTableBackupsManager implements BackupsManager {
  private static final DateTimeFormatter BACKUP_ID_FORMATTER = DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'", Locale.US).withZone(ZoneOffset.UTC);

  private final BigtableTableAdminClient client;
  private final String clusterId;
  private final Collection<String> tableIds;

  public BigTableBackupsManager(BigtableTableAdminClient client, String clusterId, Collection<String> tableIds) {
    this.client = client;
    this.clusterId = clusterId;
    this.tableIds = tableIds;
  }

  public CompletableFuture<Map<String, Backup>> createBackups() {
    final Instant backupTime = Instant.now();
    final Instant expireTime = backupTime.plus(7, ChronoUnit.DAYS);
    final ArrayList<CompletableFuture<Pair<String, Backup>>> futures = new ArrayList<>(tableIds.size());
    for (String tableId : tableIds) {
      final CreateBackupRequest request = CreateBackupRequest.of(clusterId, createBackupId(tableId, backupTime));
      request.setExpireTime(convertInstantToBigtableInstant(expireTime));
      request.setSourceTableId(tableId);
      final CompletableFuture<Pair<String, Backup>> completableFuture = new CompletableFuture<>();
      final ApiFuture<Backup> apiFuture = client.createBackupAsync(request);
      ApiFutures.addCallback(apiFuture, new ApiFutureCallback<>() {
        @Override
        public void onFailure(Throwable t) {
          completableFuture.completeExceptionally(t);
        }

        @Override
        public void onSuccess(Backup result) {
          completableFuture.complete(new Pair<>(tableId, result));
        }
      }, MoreExecutors.directExecutor());
      futures.add(completableFuture);
    }
    final CompletableFuture<Void> completableFuture = CompletableFuture.allOf(futures.toArray(new CompletableFuture[0]));
    return completableFuture.thenApply(v -> futures.stream()
                                                   .map(CompletableFuture::join)
                                                   .collect(Collectors.toMap(Pair::first, Pair::second)));
  }

  private static String createBackupId(final String tableId, final Instant backupTime) {
    return BACKUP_ID_FORMATTER.format(backupTime) + '-' + tableId;
  }

  private static org.threeten.bp.Instant convertInstantToBigtableInstant(final Instant instant) {
    return org.threeten.bp.Instant.ofEpochSecond(instant.getEpochSecond(), instant.getNano());
  }
}
