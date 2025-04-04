/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.controllers;

import com.codahale.metrics.annotation.Timed;
import io.dropwizard.auth.Auth;
import java.time.Clock;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.DefaultValue;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.HeaderParam;
import jakarta.ws.rs.PATCH;
import jakarta.ws.rs.PUT;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.QueryParam;
import jakarta.ws.rs.core.Response;
import org.signal.libsignal.zkgroup.ServerSecretParams;
import org.signal.storageservice.auth.ExternalGroupCredentialGenerator;
import org.signal.storageservice.auth.GroupUser;
import org.signal.storageservice.configuration.GroupConfiguration;
import org.signal.storageservice.providers.NoUnknownFields;
import org.signal.storageservice.providers.ProtocolBufferMediaType;
import org.signal.storageservice.s3.PolicySigner;
import org.signal.storageservice.s3.PostPolicyGenerator;
import org.signal.storageservice.storage.GroupsManager;
import org.signal.storageservice.storage.protos.groups.Group;
import org.signal.storageservice.storage.protos.groups.GroupChange;
import org.signal.storageservice.storage.protos.groups.GroupChangeResponse;
import org.signal.storageservice.storage.protos.groups.GroupResponse;
import org.signal.storageservice.storage.protos.groups.GroupChanges;

@Path("/v1/groups")
public class GroupsV1Controller extends GroupsController {

  public GroupsV1Controller(
      Clock clock,
      GroupsManager groupsManager,
      ServerSecretParams serverSecretParams,
      PolicySigner policySigner,
      PostPolicyGenerator policyGenerator,
      GroupConfiguration groupConfiguration,
      ExternalGroupCredentialGenerator externalGroupCredentialGenerator) {
    super(clock, groupsManager, serverSecretParams, policySigner, policyGenerator, groupConfiguration, externalGroupCredentialGenerator);
  }

  @Override
  @Timed
  @GET
  @Produces(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
  public CompletableFuture<Response> getGroup(@Auth GroupUser user) {
    return super.getGroup(user)
        .thenApply(response -> {
              if (response.getEntity() instanceof final GroupResponse gr) {
                return Response.fromResponse(response).entity(gr.getGroup()).build();
              }
              return response;
            });
  }

  @Override
  @Timed
  @GET
  @Produces(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
  @Path("/logs/{fromVersion}")
  public CompletableFuture<Response> getGroupLogs(
      @Auth GroupUser user,
      @HeaderParam(jakarta.ws.rs.core.HttpHeaders.USER_AGENT) String userAgent,
      @HeaderParam("Cached-Send-Endorsements") Long ignored_usedByV2Only,
      @PathParam("fromVersion") int fromVersion,
      @QueryParam("limit") @DefaultValue("64") int limit,
      @QueryParam("maxSupportedChangeEpoch") Optional<Integer> maxSupportedChangeEpoch,
      @QueryParam("includeFirstState") boolean includeFirstState,
      @QueryParam("includeLastState") boolean includeLastState) {
    return super.getGroupLogs(user, userAgent, Instant.now().getEpochSecond(), fromVersion, limit, maxSupportedChangeEpoch, includeFirstState, includeLastState)
        .thenApply(response -> {
              if (response.getEntity() instanceof final GroupChanges gc) {
                return Response.fromResponse(response).entity(gc.toBuilder().clearGroupSendEndorsementsResponse().build()).build();
              }
              return response;
            });
  }

  @Override
  @Timed
  @PUT
  @Produces(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
  @Consumes(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
  public CompletableFuture<Response> createGroup(@Auth GroupUser user, @NoUnknownFields Group group) {
    return super.createGroup(user, group)
        .thenApply(response -> Response.fromResponse(response).entity(null).build());
  }

  @Override
  @Timed
  @PATCH
  @Produces(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
  @Consumes(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
  public CompletableFuture<Response> modifyGroup(
      @Auth GroupUser user,
      @QueryParam("inviteLinkPassword") String inviteLinkPasswordString,
      @NoUnknownFields GroupChange.Actions submittedActions) {
    return super.modifyGroup(user, inviteLinkPasswordString, submittedActions)
        .thenApply(response -> {
              if (response.getEntity() instanceof final GroupChangeResponse gcr) {
                return Response.fromResponse(response).entity(gcr.getGroupChange()).build();
              }
              return response;
            });
  }

}
