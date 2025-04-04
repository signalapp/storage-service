/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.controllers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

import com.google.api.client.util.Clock;
import com.google.protobuf.ByteString;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import org.signal.storageservice.configuration.GroupConfiguration;
import org.signal.storageservice.providers.ProtocolBufferMediaType;
import org.signal.storageservice.storage.protos.groups.AccessControl;
import org.signal.storageservice.storage.protos.groups.Group;
import org.signal.storageservice.storage.protos.groups.GroupChange;
import org.signal.storageservice.storage.protos.groups.GroupJoinInfo;
import org.signal.storageservice.storage.protos.groups.Member;
import org.signal.storageservice.storage.protos.groups.MemberPendingProfileKey;
import org.signal.storageservice.util.AuthHelper;

class GroupsControllerMaxSizeTest extends BaseGroupsControllerTest {
  @Override
  protected GroupConfiguration getGroupConfiguration() {
    final GroupConfiguration base = super.getGroupConfiguration();
    return new GroupConfiguration(2, base.maxGroupTitleLengthBytes(), base.maxGroupDescriptionLengthBytes(), base.externalServiceSecret(), base.groupSendEndorsementExpirationTime(), base.groupSendEndorsementMinimumLifetime());
  }

  @Test
  void testAddMemberWhenTooMany() {
    setupGroupsManagerBehaviors(group);

    GroupChange.Actions groupChange = GroupChange.Actions.newBuilder()
                                                         .setVersion(1)
                                                         .addAddMembers(GroupChange.Actions.AddMemberAction.newBuilder()
                                                                                                           .setAdded(Member.newBuilder()
                                                                                                                           .setPresentation(ByteString.copyFrom(validUserThreePresentation.serialize()))
                                                                                                                           .setRole(Member.Role.DEFAULT)
                                                                                                                           .build()))
                                                         .build();

    Response response = resources.getJerseyTest()
                                 .target("/v1/groups/")
                                 .request(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
                                 .header("Authorization", AuthHelper.getAuthHeader(groupSecretParams, AuthHelper.VALID_USER_AUTH_CREDENTIAL))
                                 .method("PATCH", Entity.entity(groupChange.toByteArray(), ProtocolBufferMediaType.APPLICATION_PROTOBUF));

    assertThat(response.getStatus()).isEqualTo(400);
    verify(groupsManager).getGroup(eq(ByteString.copyFrom(groupPublicParams.getGroupIdentifier().serialize())));
    verifyNoMoreInteractions(groupsManager);
  }

  @Test
  void testAddMemberWhenMembersPendingProfileKey() {
    Group group = Group.newBuilder()
                       .setPublicKey(ByteString.copyFrom(groupPublicParams.serialize()))
                       .setAccessControl(AccessControl.newBuilder()
                                                      .setMembers(AccessControl.AccessRequired.MEMBER)
                                                      .setAttributes(AccessControl.AccessRequired.MEMBER))
                       .setTitle(ByteString.copyFromUtf8("Some title"))
                       .setAvatar(avatarFor(groupPublicParams.getGroupIdentifier().serialize()))
                       .setVersion(0)
                       .addMembers(Member.newBuilder()
                                         .setUserId(ByteString.copyFrom(validUserPresentation.getUuidCiphertext().serialize()))
                                         .setProfileKey(ByteString.copyFrom(validUserPresentation.getProfileKeyCiphertext().serialize()))
                                         .setRole(Member.Role.ADMINISTRATOR)
                                         .setJoinedAtVersion(0)
                                         .build())
                       .addMembersPendingProfileKey(MemberPendingProfileKey.newBuilder()
                                                                           .setMember(Member.newBuilder()
                                                                                            .setUserId(ByteString.copyFrom(validUserTwoPresentation.getUuidCiphertext().serialize()))
                                                                                            .setRole(Member.Role.DEFAULT)
                                                                                            .build())
                                                                           .setAddedByUserId(ByteString.copyFrom(validUserPresentation.getUuidCiphertext().serialize()))
                                                                           .setTimestamp(Clock.SYSTEM.currentTimeMillis())
                                                                           .build())
                       .build();

    setupGroupsManagerBehaviors(group);

    GroupChange.Actions groupChange = GroupChange.Actions.newBuilder()
                                                         .setVersion(1)
                                                         .addAddMembers(GroupChange.Actions.AddMemberAction.newBuilder()
                                                                                                           .setAdded(Member.newBuilder()
                                                                                                                           .setPresentation(ByteString.copyFrom(validUserThreePresentation.serialize()))
                                                                                                                           .setRole(Member.Role.DEFAULT)
                                                                                                                           .build()))
                                                         .build();

    Response response = resources.getJerseyTest()
                                 .target("/v1/groups/")
                                 .request(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
                                 .header("Authorization", AuthHelper.getAuthHeader(groupSecretParams, AuthHelper.VALID_USER_AUTH_CREDENTIAL))
                                 .method("PATCH", Entity.entity(groupChange.toByteArray(), ProtocolBufferMediaType.APPLICATION_PROTOBUF));

    assertThat(response.getStatus()).isEqualTo(400);
    verify(groupsManager).getGroup(eq(ByteString.copyFrom(groupPublicParams.getGroupIdentifier().serialize())));
    verifyNoMoreInteractions(groupsManager);
  }

  @Test
  void testGetGroupJoinInfo() throws Exception {
    final byte[] inviteLinkPassword = new byte[16];
    new SecureRandom().nextBytes(inviteLinkPassword);
    final String inviteLinkPasswordString = Base64.getUrlEncoder().encodeToString(inviteLinkPassword);

    final Group.Builder groupBuilder = Group.newBuilder();
    groupBuilder.setPublicKey(ByteString.copyFrom(groupPublicParams.serialize()));
    groupBuilder.getAccessControlBuilder().setMembers(AccessControl.AccessRequired.MEMBER);
    groupBuilder.getAccessControlBuilder().setAttributes(AccessControl.AccessRequired.MEMBER);
    groupBuilder.setTitle(ByteString.copyFromUtf8("Some title"));
    groupBuilder.setDescription(ByteString.copyFromUtf8("Some description"));
    final String avatar = avatarFor(groupPublicParams.getGroupIdentifier().serialize());
    groupBuilder.setAvatar(avatar);
    groupBuilder.setVersion(0);
    groupBuilder.addMembersBuilder()
        .setUserId(ByteString.copyFrom(validUserPresentation.getUuidCiphertext().serialize()))
        .setProfileKey(ByteString.copyFrom(validUserPresentation.getProfileKeyCiphertext().serialize()))
        .setRole(Member.Role.ADMINISTRATOR)
        .setJoinedAtVersion(0);
    groupBuilder.addMembersPendingAdminApprovalBuilder()
        .setUserId(ByteString.copyFrom(validUserTwoPresentation.getUuidCiphertext().serialize()))
        .setProfileKey(ByteString.copyFrom(validUserTwoPresentation.getProfileKeyCiphertext().serialize()))
        .setTimestamp(1);
    groupBuilder.addMembersPendingAdminApprovalBuilder()
        .setUserId(ByteString.copyFrom(validUserThreePresentation.getUuidCiphertext().serialize()))
        .setProfileKey(ByteString.copyFrom(validUserThreePresentation.getProfileKeyCiphertext().serialize()))
        .setTimestamp(2);

    setMockGroupState(groupBuilder);

    Response response = resources.getJerseyTest()
        .target("/v1/groups/join/" + inviteLinkPasswordString)
        .request(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
        .header("Authorization", AuthHelper.getAuthHeader(groupSecretParams, AuthHelper.VALID_USER_FOUR_AUTH_CREDENTIAL))
        .get();

    assertThat(response.getStatus()).isEqualTo(403);
    assertThat(response.hasEntity()).isFalse();

    groupBuilder.setInviteLinkPassword(ByteString.copyFrom(inviteLinkPassword));

    setMockGroupState(groupBuilder);

    response = resources.getJerseyTest()
        .target("/v1/groups/join/" + inviteLinkPasswordString)
        .request(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
        .header("Authorization", AuthHelper.getAuthHeader(groupSecretParams, AuthHelper.VALID_USER_FOUR_AUTH_CREDENTIAL))
        .get();

    assertThat(response.getStatus()).isEqualTo(403);
    assertThat(response.hasEntity()).isFalse();

    groupBuilder.getAccessControlBuilder().setAddFromInviteLink(AccessControl.AccessRequired.ANY);
    groupBuilder.setVersion(42);

    setMockGroupState(groupBuilder);

    response = resources.getJerseyTest()
        .target("/v1/groups/join/" + inviteLinkPasswordString)
        .request(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
        .header("Authorization", AuthHelper.getAuthHeader(groupSecretParams, AuthHelper.VALID_USER_FOUR_AUTH_CREDENTIAL))
        .get();

    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.hasEntity()).isTrue();
    assertThat(response.getMediaType().toString()).isEqualTo("application/x-protobuf");
    GroupJoinInfo groupJoinInfo = GroupJoinInfo.parseFrom(response.readEntity(InputStream.class).readAllBytes());
    assertThat(groupJoinInfo.getPublicKey().toByteArray()).isEqualTo(groupPublicParams.serialize());
    assertThat(groupJoinInfo.getTitle().toByteArray()).isEqualTo("Some title".getBytes(StandardCharsets.UTF_8));
    assertThat(groupJoinInfo.getDescription().toByteArray()).isEqualTo("Some description".getBytes(StandardCharsets.UTF_8));
    assertThat(groupJoinInfo.getAvatar()).isEqualTo(avatar);
    assertThat(groupJoinInfo.getMemberCount()).isEqualTo(1);
    assertThat(groupJoinInfo.getAddFromInviteLink()).isEqualTo(AccessControl.AccessRequired.ANY);
    assertThat(groupJoinInfo.getVersion()).isEqualTo(42);
    assertThat(groupJoinInfo.getPendingAdminApproval()).isFalse();
    assertThat(groupJoinInfo.getPendingAdminApprovalFull()).isTrue();

    groupBuilder.setVersion(0);

    setMockGroupState(groupBuilder);

    response = resources.getJerseyTest()
        .target("/v1/groups/join/foo" + inviteLinkPasswordString)
        .request(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
        .header("Authorization", AuthHelper.getAuthHeader(groupSecretParams, AuthHelper.VALID_USER_FOUR_AUTH_CREDENTIAL))
        .get();

    assertThat(response.getStatus()).isEqualTo(403);
    assertThat(response.hasEntity()).isFalse();

    groupBuilder.getAccessControlBuilder().setAddFromInviteLink(AccessControl.AccessRequired.UNSATISFIABLE);

    setMockGroupState(groupBuilder);

    response = resources.getJerseyTest()
        .target("/v1/groups/join/" + inviteLinkPasswordString)
        .request(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
        .header("Authorization", AuthHelper.getAuthHeader(groupSecretParams, AuthHelper.VALID_USER_FOUR_AUTH_CREDENTIAL))
        .get();

    assertThat(response.getStatus()).isEqualTo(403);
    assertThat(response.hasEntity()).isFalse();

    groupBuilder.addMembersPendingAdminApprovalBuilder()
        .setUserId(ByteString.copyFrom(validUserFourPresentation.getUuidCiphertext().serialize()))
        .setProfileKey(ByteString.copyFrom(validUserFourPresentation.getProfileKeyCiphertext().serialize()))
        .setTimestamp(System.currentTimeMillis());

    setMockGroupState(groupBuilder);

    response = resources.getJerseyTest()
        .target("/v1/groups/join/" + inviteLinkPasswordString)
        .request(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
        .header("Authorization", AuthHelper.getAuthHeader(groupSecretParams, AuthHelper.VALID_USER_FOUR_AUTH_CREDENTIAL))
        .get();

    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.hasEntity()).isTrue();
    assertThat(response.getMediaType().toString()).isEqualTo("application/x-protobuf");
    groupJoinInfo = GroupJoinInfo.parseFrom(response.readEntity(InputStream.class).readAllBytes());
    assertThat(groupJoinInfo.getPublicKey().toByteArray()).isEqualTo(groupPublicParams.serialize());
    assertThat(groupJoinInfo.getTitle().toByteArray()).isEqualTo("Some title".getBytes(StandardCharsets.UTF_8));
    assertThat(groupJoinInfo.getDescription().toByteArray()).isEqualTo("Some description".getBytes(StandardCharsets.UTF_8));
    assertThat(groupJoinInfo.getAvatar()).isEqualTo(avatar);
    assertThat(groupJoinInfo.getMemberCount()).isEqualTo(1);
    assertThat(groupJoinInfo.getAddFromInviteLink()).isEqualTo(AccessControl.AccessRequired.UNSATISFIABLE);
    assertThat(groupJoinInfo.getVersion()).isEqualTo(0);
    assertThat(groupJoinInfo.getPendingAdminApproval()).isTrue();
    assertThat(groupJoinInfo.getPendingAdminApprovalFull()).isTrue();

    setMockGroupState(groupBuilder);

    response = resources.getJerseyTest()
        .target("/v1/groups/join/")
        .request(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
        .header("Authorization", AuthHelper.getAuthHeader(groupSecretParams, AuthHelper.VALID_USER_FOUR_AUTH_CREDENTIAL))
        .get();

    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.hasEntity()).isTrue();
    assertThat(response.getMediaType().toString()).isEqualTo("application/x-protobuf");
    groupJoinInfo = GroupJoinInfo.parseFrom(response.readEntity(InputStream.class).readAllBytes());
    assertThat(groupJoinInfo.getPublicKey().toByteArray()).isEqualTo(groupPublicParams.serialize());
    assertThat(groupJoinInfo.getTitle().toByteArray()).isEqualTo("Some title".getBytes(StandardCharsets.UTF_8));
    assertThat(groupJoinInfo.getDescription().toByteArray()).isEqualTo("Some description".getBytes(StandardCharsets.UTF_8));
    assertThat(groupJoinInfo.getAvatar()).isEqualTo(avatar);
    assertThat(groupJoinInfo.getMemberCount()).isEqualTo(1);
    assertThat(groupJoinInfo.getAddFromInviteLink()).isEqualTo(AccessControl.AccessRequired.UNSATISFIABLE);
    assertThat(groupJoinInfo.getVersion()).isEqualTo(0);
    assertThat(groupJoinInfo.getPendingAdminApproval()).isTrue();
    assertThat(groupJoinInfo.getPendingAdminApprovalFull()).isTrue();

    groupBuilder.removeMembersPendingAdminApproval(0).removeMembersPendingAdminApproval(0);

    setMockGroupState(groupBuilder);

    response = resources.getJerseyTest()
        .target("/v1/groups/join/")
        .request(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
        .header("Authorization", AuthHelper.getAuthHeader(groupSecretParams, AuthHelper.VALID_USER_FOUR_AUTH_CREDENTIAL))
        .get();

    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.hasEntity()).isTrue();
    assertThat(response.getMediaType().toString()).isEqualTo("application/x-protobuf");
    groupJoinInfo = GroupJoinInfo.parseFrom(response.readEntity(InputStream.class).readAllBytes());
    assertThat(groupJoinInfo.getPublicKey().toByteArray()).isEqualTo(groupPublicParams.serialize());
    assertThat(groupJoinInfo.getTitle().toByteArray()).isEqualTo("Some title".getBytes(StandardCharsets.UTF_8));
    assertThat(groupJoinInfo.getDescription().toByteArray()).isEqualTo("Some description".getBytes(StandardCharsets.UTF_8));
    assertThat(groupJoinInfo.getAvatar()).isEqualTo(avatar);
    assertThat(groupJoinInfo.getMemberCount()).isEqualTo(1);
    assertThat(groupJoinInfo.getAddFromInviteLink()).isEqualTo(AccessControl.AccessRequired.UNSATISFIABLE);
    assertThat(groupJoinInfo.getVersion()).isEqualTo(0);
    assertThat(groupJoinInfo.getPendingAdminApproval()).isTrue();
    assertThat(groupJoinInfo.getPendingAdminApprovalFull()).isFalse();
  }
}
