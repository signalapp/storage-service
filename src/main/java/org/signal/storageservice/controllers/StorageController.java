/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.controllers;

import static com.codahale.metrics.MetricRegistry.name;

import com.codahale.metrics.annotation.Timed;
import com.google.common.annotations.VisibleForTesting;
import io.dropwizard.auth.Auth;
import io.micrometer.core.instrument.DistributionSummary;
import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.Tags;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.HttpHeaders;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import org.signal.storageservice.auth.User;
import org.signal.storageservice.metrics.UserAgentTagUtil;
import org.signal.storageservice.providers.ProtocolBufferMediaType;
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
  static final int MAX_MUTATIONS = 100_000;

  private static final String INSERT_DISTRIBUTION_SUMMARY_NAME = name(StorageController.class, "inserts");
  private static final String DELETE_DISTRIBUTION_SUMMARY_NAME = name(StorageController.class, "deletes");
  private static final String READ_DISTRIBUTION_SUMMARY_NAME = name(StorageController.class, "reads");

  public StorageController(StorageManager storageManager) {
    this.storageManager = storageManager;
  }

  @Timed
  @GET
  @Path("/manifest")
  @Produces(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
  public CompletableFuture<StorageManifest> getManifest(@Auth User user) {
    return storageManager.getManifest(user)
                         .thenApply(manifest -> manifest.orElseThrow(() -> new WebApplicationException(Response.Status.NOT_FOUND)));
  }

  @Timed
  @GET
  @Path("/manifest/version/{version}")
  @Produces(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
  public CompletableFuture<StorageManifest> getManifest(@Auth User user, @PathParam("version") long version) {
    return storageManager.getManifestIfNotVersion(user, version)
                         .thenApply(manifest -> manifest.orElseThrow(() -> new WebApplicationException(Response.Status.NO_CONTENT)));
  }


  @Timed
  @PUT
  @Consumes(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
  @Produces(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
  public CompletableFuture<Response> write(@Auth User user, @HeaderParam(HttpHeaders.USER_AGENT) String userAgent, WriteOperation writeOperation) {
    if (!writeOperation.hasManifest()) {
      return CompletableFuture.failedFuture(new WebApplicationException(Response.Status.BAD_REQUEST));
    }

    distributionSummary(INSERT_DISTRIBUTION_SUMMARY_NAME, userAgent).record(writeOperation.getInsertItemCount());
    distributionSummary(DELETE_DISTRIBUTION_SUMMARY_NAME, userAgent).record(writeOperation.getDeleteKeyCount());

    if (writeOperation.getInsertItemCount() + writeOperation.getDeleteKeyCount() > MAX_MUTATIONS) {
      return CompletableFuture.failedFuture(new WebApplicationException(Status.REQUEST_ENTITY_TOO_LARGE));
    }

    CompletableFuture<Void> future;

    if (writeOperation.getClearAll()) {
      future = storageManager.clearItems(user);
    } else {
      future = CompletableFuture.completedFuture(null);
    }

    return future.thenCompose(ignored -> storageManager.set(user, writeOperation.getManifest(), writeOperation.getInsertItemList(), writeOperation.getDeleteKeyList()))
                 .thenApply(manifest -> {
                   if (manifest.isPresent())
                     return Response.status(409).entity(manifest.get()).build();
                   else return Response.status(200).build();
                 });
  }

  private static DistributionSummary distributionSummary(final String name, final String userAgent) {
    return DistributionSummary.builder(name)
        .publishPercentiles(0.75, 0.95, 0.99, 0.999)
        .distributionStatisticExpiry(Duration.ofMinutes(5))
        .tags(Tags.of(UserAgentTagUtil.getPlatformTag(userAgent)))
        .register(Metrics.globalRegistry);
  }

  @Timed
  @PUT
  @Path("/read")
  @Consumes(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
  @Produces(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
  public CompletableFuture<StorageItems> read(@Auth User user, @HeaderParam(HttpHeaders.USER_AGENT) String userAgent, ReadOperation readOperation) {
    if (readOperation.getReadKeyList().isEmpty()) {
      return CompletableFuture.failedFuture(new WebApplicationException(Response.Status.BAD_REQUEST));
    }

    distributionSummary(READ_DISTRIBUTION_SUMMARY_NAME, userAgent).record(readOperation.getReadKeyCount());

    if (readOperation.getReadKeyCount() > MAX_READ_KEYS) {
      return CompletableFuture.failedFuture(new WebApplicationException(Status.REQUEST_ENTITY_TOO_LARGE));
    }

    return storageManager.getItems(user, readOperation.getReadKeyList())
                         .thenApply(items -> StorageItems.newBuilder().addAllContacts(items).build());
  }

  @Timed
  @DELETE
  public CompletableFuture<Response> delete(@Auth User user) {
    return storageManager.delete(user).thenApply(v -> Response.status(Response.Status.OK).build());
  }
}
