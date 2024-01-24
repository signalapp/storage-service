/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.controllers;

import com.codahale.metrics.annotation.Timed;
import io.dropwizard.auth.Auth;
import java.time.Clock;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import javax.ws.rs.Consumes;
import javax.ws.rs.DefaultValue;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.PATCH;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Response;
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
      @HeaderParam(javax.ws.rs.core.HttpHeaders.USER_AGENT) String userAgent,
      @PathParam("fromVersion") int fromVersion,
      @QueryParam("limit") @DefaultValue("64") int limit,
      @QueryParam("maxSupportedChangeEpoch") Optional<Integer> maxSupportedChangeEpoch,
      @QueryParam("includeFirstState") boolean includeFirstState,
      @QueryParam("includeLastState") boolean includeLastState) {
    return super.getGroupLogs(user, userAgent, fromVersion, limit, maxSupportedChangeEpoch, includeFirstState, includeLastState)
        .thenApply(response -> {
              if (response.getEntity() instanceof final GroupChanges gc) {
                return Response.fromResponse(response).entity(gc.toBuilder().clearGroupSendCredentialResponse().build()).build();
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
