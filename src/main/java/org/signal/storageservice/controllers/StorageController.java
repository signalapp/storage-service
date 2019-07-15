/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.controllers;

import com.codahale.metrics.annotation.Timed;
import io.dropwizard.auth.Auth;
import org.signal.storageservice.auth.User;
import org.signal.storageservice.providers.ProtocolBufferMediaType;
import org.signal.storageservice.storage.StorageManager;
import org.signal.storageservice.storage.protos.contacts.ReadOperation;
import org.signal.storageservice.storage.protos.contacts.StorageItems;
import org.signal.storageservice.storage.protos.contacts.StorageManifest;
import org.signal.storageservice.storage.protos.contacts.WriteOperation;

import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import java.util.concurrent.CompletableFuture;

@Path("/v1/storage")
public class StorageController {

  private final StorageManager storageManager;

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
  public CompletableFuture<Response> write(@Auth User user, WriteOperation writeOperation) {
    if (!writeOperation.hasManifest()) {
      return CompletableFuture.failedFuture(new WebApplicationException(Response.Status.BAD_REQUEST));
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

  @Timed
  @PUT
  @Path("/read")
  @Consumes(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
  @Produces(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
  public CompletableFuture<StorageItems> read(@Auth User user, ReadOperation readOperation) {
    if (readOperation.getReadKeyList().isEmpty()) {
      return CompletableFuture.failedFuture(new WebApplicationException(Response.Status.BAD_REQUEST));
    }

    return storageManager.getItems(user, readOperation.getReadKeyList())
                         .thenApply(items -> StorageItems.newBuilder().addAllContacts(items).build());
  }

}
