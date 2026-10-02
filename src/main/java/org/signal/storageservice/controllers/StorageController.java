/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.controllers;

import static org.signal.storageservice.metrics.MetricsUtil.name;

import com.google.common.annotations.VisibleForTesting;
import io.dropwizard.auth.Auth;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.Tags;
import io.micrometer.core.instrument.Timer;
import jakarta.validation.constraints.NotNull;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DELETE;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.Response.Status;
import java.util.concurrent.CompletableFuture;
import org.signal.storageservice.auth.User;
import org.signal.storageservice.metrics.UserAgentTagUtil;
import org.signal.storageservice.providers.ProtocolBufferMediaType;
import org.signal.storageservice.storage.StorageItemsTable;
import org.signal.storageservice.storage.StorageManager;
import org.signal.storageservice.storage.protos.contacts.ReadOperation;
import org.signal.storageservice.storage.protos.contacts.StorageItems;
import org.signal.storageservice.storage.protos.contacts.StorageManifest;
import org.signal.storageservice.storage.protos.contacts.WriteOperation;

@Path("/v1/storage")
public class StorageController {

  private final StorageManager storageManager;

  @VisibleForTesting
  static final int MAX_READ_KEYS = 5120;
  // https://cloud.google.com/bigtable/quotas#limits-operations

  @VisibleForTesting
  static final int MAX_BULK_MUTATION_PAGES = 10;

  private static final String INSERT_DISTRIBUTION_SUMMARY_NAME = name(StorageController.class, "inserts");
  private static final String DELETE_DISTRIBUTION_SUMMARY_NAME = name(StorageController.class, "deletes");
  private static final String MUTATION_DISTRIBUTION_SUMMARY_NAME = name(StorageController.class, "mutations");
  private static final String READ_DISTRIBUTION_SUMMARY_NAME = name(StorageController.class, "reads");
  private static final String WRITE_REQUEST_SIZE_DISTRIBUTION_SUMMARY_NAME = name(StorageController.class, "writeRequestBytes");

  private static final String CLEAR_ALL_REQUEST_COUNTER_NAME = name(StorageController.class, "writeRequestClearAll");

  public StorageController(StorageManager storageManager) {
    this.storageManager = storageManager;
  }

  @GET
  @Path("/manifest")
  @Produces(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
  public CompletableFuture<StorageManifest> getManifest(@Auth User user) {
    final Timer.Sample sample = Timer.start();
    return storageManager.getManifest(user)
      .thenApply(manifest -> manifest.orElseThrow(() -> new WebApplicationException(Response.Status.NOT_FOUND)))
      .whenComplete((_result, _throwable) -> sample.stop(Metrics.timer(name(StorageController.class, "getManifest"))));
  }

  @GET
  @Path("/manifest/version/{version}")
  @Produces(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
  public CompletableFuture<StorageManifest> getManifest(@Auth User user, @PathParam("version") long version) {
    final Timer.Sample sample = Timer.start();
    return storageManager.getManifestIfNotVersion(user, version)
      .thenApply(manifest -> manifest.orElseThrow(() -> new WebApplicationException(Response.Status.NO_CONTENT)))
      .whenComplete((_result, _throwable) -> sample.stop(Metrics.timer(name(StorageController.class, "getManifest"))));
  }


  @PUT
  @Consumes(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
  @Produces(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
  public CompletableFuture<Response> write(@Auth User user,
                                           @HeaderParam(HttpHeaders.USER_AGENT) String userAgent,
                                           @QueryParam("sendRemoteManifestOnConflict") @DefaultValue("true") boolean sendRemoteManifestOnConflict,
                                           @NotNull WriteOperation writeOperation) {
    final Timer timer = Metrics.timer(name(StorageController.class, "write"));
    final Timer.Sample sample = Timer.start();

    if (!writeOperation.hasManifest()) {
      sample.stop(timer);
      return CompletableFuture.failedFuture(new WebApplicationException(Response.Status.BAD_REQUEST));
    }

    distributionSummary(INSERT_DISTRIBUTION_SUMMARY_NAME, userAgent).record(writeOperation.getInsertItemCount());
    distributionSummary(DELETE_DISTRIBUTION_SUMMARY_NAME, userAgent).record(writeOperation.getDeleteKeyCount());
    distributionSummary(WRITE_REQUEST_SIZE_DISTRIBUTION_SUMMARY_NAME, userAgent).record(writeOperation.getSerializedSize());

    if (writeOperation.getClearAll()) {
      Metrics.counter(CLEAR_ALL_REQUEST_COUNTER_NAME, Tags.of(UserAgentTagUtil.getPlatformTag(userAgent))).increment();
    }

    final int mutations =
        writeOperation.getInsertItemCount() * StorageItemsTable.MUTATIONS_PER_INSERT + writeOperation.getDeleteKeyCount();

    distributionSummary(MUTATION_DISTRIBUTION_SUMMARY_NAME, userAgent).record(mutations);

    if (mutations > StorageItemsTable.MAX_MUTATIONS * MAX_BULK_MUTATION_PAGES) {
      sample.stop(timer);
      return CompletableFuture.failedFuture(new WebApplicationException(Status.REQUEST_ENTITY_TOO_LARGE));
    }

    final CompletableFuture<Void> clearAllFuture = writeOperation.getClearAll()
        ? storageManager.clearItems(user)
        : CompletableFuture.completedFuture(null);

    return clearAllFuture.thenCompose(ignored -> storageManager.set(user, writeOperation.getManifest(), writeOperation.getInsertItemList(), writeOperation.getDeleteKeyList()))
      .thenApply(
        manifest -> {
          if (manifest.isPresent()) {
            // Clients that would fetch the manifest again anyway can opt out of receiving it here, since it can be sizable.
            final Response.ResponseBuilder conflict = Response.status(409);
            if (sendRemoteManifestOnConflict) {
              conflict.entity(manifest.get());
            }
            return conflict.build();
          } else {
            return Response.status(200).build();
          }
        }).whenComplete((_result, _throwable) -> sample.stop(timer));
  }

  private static DistributionSummary distributionSummary(final String name, final String userAgent) {
    return DistributionSummary.builder(name)
        .tags(Tags.of(UserAgentTagUtil.getPlatformTag(userAgent)))
        .register(Metrics.globalRegistry);
  }

  @PUT
  @Path("/read")
  @Consumes(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
  @Produces(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
  public CompletableFuture<StorageItems> read(@Auth User user, @HeaderParam(HttpHeaders.USER_AGENT) String userAgent, @NotNull ReadOperation readOperation) {
    final Timer timer = Metrics.timer(name(StorageController.class, "read"));
    final Timer.Sample sample = Timer.start();

    if (readOperation.getReadKeyList().isEmpty()) {
      sample.stop(timer);
      return CompletableFuture.failedFuture(new WebApplicationException(Response.Status.BAD_REQUEST));
    }

    distributionSummary(READ_DISTRIBUTION_SUMMARY_NAME, userAgent).record(readOperation.getReadKeyCount());

    if (readOperation.getReadKeyCount() > MAX_READ_KEYS) {
      sample.stop(timer);
      return CompletableFuture.failedFuture(new WebApplicationException(Status.REQUEST_ENTITY_TOO_LARGE));
    }

    return storageManager.getItems(user, readOperation.getReadKeyList())
      .thenApply(items -> StorageItems.newBuilder().addAllContacts(items).build())
      .whenComplete((_result, _throwable) -> sample.stop(timer));
  }

  @DELETE
  public CompletableFuture<Response> delete(@Auth User user) {
    final Timer.Sample sample = Timer.start();
    return storageManager.delete(user).thenApply(v -> Response.status(Response.Status.OK).build())
      .whenComplete((_result, _throwable) -> sample.stop(Metrics.timer(name(StorageController.class, "delete"))));
  }
}
