/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.controllers;

import com.google.cloud.bigtable.admin.v2.models.Backup;
import org.signal.storageservice.storage.BackupsManager;

import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.Path;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

@Path("/backup")
public class BackupsController {

  private final BackupsManager backupsManager;

  public BackupsController(BackupsManager backupsManager) {
    this.backupsManager = backupsManager;
  }

  @GET
  public Response startBackup(@HeaderParam("X-Appengine-Cron") String appEngineCronValidation) throws ExecutionException, InterruptedException {

    // Google AppEngine is supposed to ensure no one else other than itself can pass this header into the service
    if (!"true".equalsIgnoreCase(appEngineCronValidation)) {
      return Response.status(Response.Status.NOT_FOUND).build();
    }

    final CompletableFuture<Map<String, Backup>> future = backupsManager.createBackups();
    try {
      future.get(5, TimeUnit.SECONDS);
      return Response.ok("OK", MediaType.TEXT_PLAIN_TYPE).build();
    } catch (TimeoutException e) {
      return Response.status(Response.Status.ACCEPTED).entity("ACCEPTED").type(MediaType.TEXT_PLAIN_TYPE).build();
    }
  }
}
