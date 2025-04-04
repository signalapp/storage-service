/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.controllers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;

import com.google.protobuf.ByteString;
import java.io.InputStream;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.function.Function;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Response;
import org.apache.commons.codec.binary.Base64;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.signal.libsignal.zkgroup.NotarySignature;
import org.signal.storageservice.providers.ProtocolBufferMediaType;
import org.signal.storageservice.storage.protos.groups.AccessControl;
import org.signal.storageservice.storage.protos.groups.Group;
import org.signal.storageservice.storage.protos.groups.GroupChange;
import org.signal.storageservice.storage.protos.groups.Member;
import org.signal.storageservice.storage.protos.groups.MemberPendingAdminApproval;
import org.signal.storageservice.storage.protos.groups.MemberPendingProfileKey;
import org.signal.storageservice.util.AuthHelper;

class GroupsControllerInviteLinkTest extends BaseGroupsControllerTest {

  private byte[] createGroupInviteLinkPassword() {
    byte[] result = new byte[16];
    new SecureRandom().nextBytes(result);
    return result;
  }

  @Test
  void testModifyAddFromInviteLinkAccessControl() throws Exception {
    setupGroupsManagerBehaviors(group);

    GroupChange.Actions groupChange = GroupChange.Actions.newBuilder()
                                                         .setVersion(1)
                                                         .setModifyAddFromInviteLinkAccess(GroupChange.Actions.ModifyAddFromInviteLinkAccessControlAction.newBuilder()
                                                                                                                                                         .setAddFromInviteLinkAccess(AccessControl.AccessRequired.ANY)
                                                                                                                                                         .build())
                                                         .setModifyInviteLinkPassword(GroupChange.Actions.ModifyInviteLinkPasswordAction.newBuilder()
                                                                                                                                        .setInviteLinkPassword(ByteString.copyFrom(createGroupInviteLinkPassword()))
                                                                                                                                        .build())
                                                         .build();

    Response response = resources.getJerseyTest()
                                 .target("/v1/groups/")
                                 .request(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
                                 .header("Authorization", AuthHelper.getAuthHeader(groupSecretParams, AuthHelper.VALID_USER_AUTH_CREDENTIAL))
                                 .method("PATCH", Entity.entity(groupChange.toByteArray(), ProtocolBufferMediaType.APPLICATION_PROTOBUF));

    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.hasEntity()).isTrue();
    assertThat(response.getMediaType().toString()).isEqualTo("application/x-protobuf");

    GroupChange signedChange = GroupChange.parseFrom(response.readEntity(InputStream.class).readAllBytes());

    ArgumentCaptor<Group>       captor       = ArgumentCaptor.forClass(Group.class      );
    ArgumentCaptor<GroupChange> changeCaptor = ArgumentCaptor.forClass(GroupChange.class);

    verify(groupsManager).updateGroup(eq(ByteString.copyFrom(groupPublicParams.getGroupIdentifier().serialize())), captor.capture());
    verify(groupsManager).appendChangeRecord(eq(ByteString.copyFrom(groupPublicParams.getGroupIdentifier().serialize())), eq(1), changeCaptor.capture(), any(Group.class));

    assertThat(captor.getValue().getVersion()).isEqualTo(1);
    assertThat(captor.getValue().getAccessControl().getAddFromInviteLink()).isSameAs(AccessControl.AccessRequired.ANY);

    assertThat(captor.getValue().toBuilder()
                     .setVersion(0)
                     .setAccessControl(captor.getValue().getAccessControl().toBuilder()
                                             .clearAddFromInviteLink()
                                             .build())
                     .clearInviteLinkPassword()
                     .build())
            .isEqualTo(group);

    assertThat(signedChange).isEqualTo(changeCaptor.getValue());
    assertThat(GroupChange.Actions.parseFrom(signedChange.getActions()).getGroupId()).isEqualTo(ByteString.copyFrom(groupPublicParams.getGroupIdentifier().serialize()));
    assertThat(GroupChange.Actions.parseFrom(signedChange.getActions()).getVersion()).isEqualTo(1);
    assertThat(GroupChange.Actions.parseFrom(signedChange.getActions()).getSourceUuid()).isEqualTo(ByteString.copyFrom(validUserPresentation.getUuidCiphertext().serialize()));
    assertThat(GroupChange.Actions.parseFrom(signedChange.getActions()).toBuilder().clearGroupId().clearSourceUuid().build()).isEqualTo(groupChange);

    AuthHelper.GROUPS_SERVER_KEY.getPublicParams().verifySignature(signedChange.getActions().toByteArray(),
                                                                   new NotarySignature(signedChange.getServerSignature().toByteArray()));
  }

  @Test
  void testModifyAddFromInviteLinkAccessControlInvalidValue() {
    setupGroupsManagerBehaviors(group);

    GroupChange.Actions groupChange = GroupChange.Actions.newBuilder()
                                                         .setVersion(1)
                                                         .setModifyAddFromInviteLinkAccess(GroupChange.Actions.ModifyAddFromInviteLinkAccessControlAction.newBuilder()
                                                                                                                                                         .setAddFromInviteLinkAccess(AccessControl.AccessRequired.MEMBER)
                                                                                                                                                         .build())
                                                         .setModifyInviteLinkPassword(GroupChange.Actions.ModifyInviteLinkPasswordAction.newBuilder()
                                                                                                                                        .setInviteLinkPassword(ByteString.copyFrom(createGroupInviteLinkPassword()))
                                                                                                                                        .build())
                                                         .build();

    Response response = resources.getJerseyTest()
                                 .target("/v1/groups/")
                                 .request(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
                                 .header("Authorization", AuthHelper.getAuthHeader(groupSecretParams, AuthHelper.VALID_USER_AUTH_CREDENTIAL))
                                 .method("PATCH", Entity.entity(groupChange.toByteArray(), ProtocolBufferMediaType.APPLICATION_PROTOBUF));

    assertThat(response.getStatus()).isEqualTo(400);
    verifyNoGroupWrites();
  }

  @Test
  void testModifyAddFromInviteLinkAccessControlUnauthorized() {
    setupGroupsManagerBehaviors(group);

    GroupChange.Actions groupChange = GroupChange.Actions.newBuilder()
                                                         .setVersion(1)
                                                         .setModifyAddFromInviteLinkAccess(GroupChange.Actions.ModifyAddFromInviteLinkAccessControlAction.newBuilder()
                                                                                                                                                         .setAddFromInviteLinkAccess(AccessControl.AccessRequired.ANY)
                                                                                                                                                         .build())
                                                         .setModifyInviteLinkPassword(GroupChange.Actions.ModifyInviteLinkPasswordAction.newBuilder()
                                                                                                                                        .setInviteLinkPassword(ByteString.copyFrom(createGroupInviteLinkPassword()))
                                                                                                                                        .build())
                                                         .build();

    Response response = resources.getJerseyTest()
                                 .target("/v1/groups/")
                                 .request(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
                                 .header("Authorization", AuthHelper.getAuthHeader(groupSecretParams, AuthHelper.VALID_USER_TWO_AUTH_CREDENTIAL))
                                 .method("PATCH", Entity.entity(groupChange.toByteArray(), ProtocolBufferMediaType.APPLICATION_PROTOBUF));

    assertThat(response.getStatus()).isEqualTo(403);
    verifyNoGroupWrites();
  }

  @Test
  void testModifyAddFromInviteLinkAccessControlNoPasswordSet() {
    setupGroupsManagerBehaviors(group);

    GroupChange.Actions groupChange = GroupChange.Actions.newBuilder()
                                                         .setVersion(1)
                                                         .setModifyAddFromInviteLinkAccess(GroupChange.Actions.ModifyAddFromInviteLinkAccessControlAction.newBuilder()
                                                                                                                                                         .setAddFromInviteLinkAccess(AccessControl.AccessRequired.ANY)
                                                                                                                                                         .build())
                                                         .build();

    Response response = resources.getJerseyTest()
                                 .target("/v1/groups/")
                                 .request(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
                                 .header("Authorization", AuthHelper.getAuthHeader(groupSecretParams, AuthHelper.VALID_USER_AUTH_CREDENTIAL))
                                 .method("PATCH", Entity.entity(groupChange.toByteArray(), ProtocolBufferMediaType.APPLICATION_PROTOBUF));

    assertThat(response.getStatus()).isEqualTo(400);
    verifyNoGroupWrites();
  }

  @Test
  void testModifyAddFromInviteLinkAccessControlSetBadPassword() {
    setupGroupsManagerBehaviors(group);

    final byte[] password = new byte[10];
    new SecureRandom().nextBytes(password);
    GroupChange.Actions groupChange = GroupChange.Actions.newBuilder()
                                                         .setVersion(1)
                                                         .setModifyAddFromInviteLinkAccess(GroupChange.Actions.ModifyAddFromInviteLinkAccessControlAction.newBuilder()
                                                                                                                                                         .setAddFromInviteLinkAccess(AccessControl.AccessRequired.ANY)
                                                                                                                                                         .build())
                                                         .setModifyInviteLinkPassword(GroupChange.Actions.ModifyInviteLinkPasswordAction.newBuilder()
                                                                                                                                        .setInviteLinkPassword(ByteString.copyFrom(password))
                                                                                                                                        .build())
                                                         .build();

    Response response = resources.getJerseyTest()
                                 .target("/v1/groups/")
                                 .request(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
                                 .header("Authorization", AuthHelper.getAuthHeader(groupSecretParams, AuthHelper.VALID_USER_AUTH_CREDENTIAL))
                                 .method("PATCH", Entity.entity(groupChange.toByteArray(), ProtocolBufferMediaType.APPLICATION_PROTOBUF));

    assertThat(response.getStatus()).isEqualTo(400);
    verifyNoGroupWrites();
  }

  private Response setupForTestAddMembersPendingAdminApproval(final byte[] inviteLinkPasswordQueryParam, final Function<Group.Builder, Group.Builder> groupBuilderFunction) {
    final Group group = groupBuilderFunction.apply(this.group.toBuilder()).build();
    setupGroupsManagerBehaviors(group);

    GroupChange.Actions actions = GroupChange.Actions.newBuilder()
                                                         .setVersion(1)
                                                         .addAddMembersPendingAdminApproval(GroupChange.Actions.AddMemberPendingAdminApprovalAction.newBuilder()
                                                                                                                                                   .setAdded(MemberPendingAdminApproval.newBuilder()
                                                                                                                                                                                       .setPresentation(ByteString.copyFrom(validUserThreePresentation.serialize()))
                                                                                                                                                                                       .build()))
                                                         .build();

    return resources.getJerseyTest()
                    .target("/v1/groups/")
                    .queryParam("inviteLinkPassword", Base64.encodeBase64URLSafeString(inviteLinkPasswordQueryParam))
                    .request(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
                    .header("Authorization", AuthHelper.getAuthHeader(groupSecretParams, AuthHelper.VALID_USER_THREE_AUTH_CREDENTIAL))
                    .method("PATCH", Entity.entity(actions.toByteArray(), ProtocolBufferMediaType.APPLICATION_PROTOBUF));
  }

  @Test
  void testAddMembersPendingAdminApproval() throws Exception {
    final byte[] inviteLinkPassword = createGroupInviteLinkPassword();
    final Function<Group.Builder, Group.Builder> groupBuilderFunction = builder -> builder.setAccessControl(this.group.getAccessControl().toBuilder().setAddFromInviteLink(AccessControl.AccessRequired.ADMINISTRATOR))
                                                                                          .setInviteLinkPassword(ByteString.copyFrom(inviteLinkPassword));
    final Response response = setupForTestAddMembersPendingAdminApproval(inviteLinkPassword, groupBuilderFunction);

    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.hasEntity()).isTrue();
    assertThat(response.getMediaType().toString()).isEqualTo("application/x-protobuf");

    GroupChange signedChange = GroupChange.parseFrom(response.readEntity(InputStream.class).readAllBytes());

    ArgumentCaptor<Group>       captor       = ArgumentCaptor.forClass(Group.class      );
    ArgumentCaptor<GroupChange> changeCaptor = ArgumentCaptor.forClass(GroupChange.class);

    verify(groupsManager).updateGroup(eq(ByteString.copyFrom(groupPublicParams.getGroupIdentifier().serialize())), captor.capture());
    verify(groupsManager).appendChangeRecord(eq(ByteString.copyFrom(groupPublicParams.getGroupIdentifier().serialize())), eq(1), changeCaptor.capture(), any(Group.class));

    assertThat(captor.getValue().getVersion()).isEqualTo(1);
    assertThat(captor.getValue().getMembersPendingAdminApprovalList()).hasSize(1).allMatch(memberPendingAdminApproval -> memberPendingAdminApproval.getUserId().equals(ByteString.copyFrom(validUserThreePresentation.getUuidCiphertext().serialize())));

    assertThat(captor.getValue().toBuilder()
                     .setVersion(0)
                     .clearMembersPendingAdminApproval()
                     .build())
            .isEqualTo(groupBuilderFunction.apply(group.toBuilder()).build());

    assertThat(signedChange).isEqualTo(changeCaptor.getValue());
    assertThat(GroupChange.Actions.parseFrom(signedChange.getActions()).getVersion()).isEqualTo(1);
    assertThat(GroupChange.Actions.parseFrom(signedChange.getActions()).getSourceUuid()).isEqualTo(ByteString.copyFrom(validUserThreePresentation.getUuidCiphertext().serialize()));

    AuthHelper.GROUPS_SERVER_KEY.getPublicParams().verifySignature(signedChange.getActions().toByteArray(),
                                                                   new NotarySignature(signedChange.getServerSignature().toByteArray()));
  }

  @Test
  void testAddMembersPendingAdminApproval_openInviteLink() {
    final byte[] inviteLinkPassword = createGroupInviteLinkPassword();
    final Response response = setupForTestAddMembersPendingAdminApproval(
            inviteLinkPassword,
            builder -> builder.setAccessControl(this.group.getAccessControl().toBuilder().setAddFromInviteLink(AccessControl.AccessRequired.ANY))
                              .setInviteLinkPassword(ByteString.copyFrom(inviteLinkPassword)));
    assertThat(response.getStatus()).isEqualTo(403);
    verifyNoGroupWrites();
  }

  @Test
  void testAddMembersPendingAdminApproval_wrongPassword() {
    final byte[] inviteLinkPassword = createGroupInviteLinkPassword();
    final byte[] wrongInviteLinkPassword = new byte[inviteLinkPassword.length];
    System.arraycopy(inviteLinkPassword, 0, wrongInviteLinkPassword, 0, wrongInviteLinkPassword.length);
    wrongInviteLinkPassword[wrongInviteLinkPassword.length - 1]++;
    final Response response = setupForTestAddMembersPendingAdminApproval(
            wrongInviteLinkPassword,
            builder -> builder.setAccessControl(this.group.getAccessControl().toBuilder().setAddFromInviteLink(AccessControl.AccessRequired.ADMINISTRATOR))
                              .setInviteLinkPassword(ByteString.copyFrom(inviteLinkPassword)));
    assertThat(response.getStatus()).isEqualTo(403);
    verifyNoGroupWrites();
  }

  @Test
  void testAddMembersPendingAdminApproval_noInviteLink() {
    final byte[] inviteLinkPassword = createGroupInviteLinkPassword();
    final Response response = setupForTestAddMembersPendingAdminApproval(inviteLinkPassword, Function.identity());
    assertThat(response.getStatus()).isEqualTo(403);
    verifyNoGroupWrites();
  }

  @Test
  void testAddMembersPendingAdminApproval_disabledInviteLink() {
    final byte[] inviteLinkPassword = createGroupInviteLinkPassword();
    final Response response = setupForTestAddMembersPendingAdminApproval(
            inviteLinkPassword,
            builder -> builder.setAccessControl(this.group.getAccessControl().toBuilder().setAddFromInviteLink(AccessControl.AccessRequired.UNSATISFIABLE))
                              .setInviteLinkPassword(ByteString.copyFrom(inviteLinkPassword)));
    assertThat(response.getStatus()).isEqualTo(403);
    verifyNoGroupWrites();
  }

  @Test
  void testAddMembersPendingAdminApproval_alreadyOnList() {
    final byte[] inviteLinkPassword = createGroupInviteLinkPassword();
    final Response response = setupForTestAddMembersPendingAdminApproval(
            inviteLinkPassword,
            builder -> builder.setAccessControl(this.group.getAccessControl().toBuilder().setAddFromInviteLink(AccessControl.AccessRequired.ADMINISTRATOR))
                              .setInviteLinkPassword(ByteString.copyFrom(inviteLinkPassword))
                              .addMembersPendingAdminApproval(MemberPendingAdminApproval.newBuilder()
                                                                                        .setUserId(ByteString.copyFrom(validUserThreePresentation.getUuidCiphertext().serialize()))
                                                                                        .setProfileKey(ByteString.copyFrom(validUserThreePresentation.getProfileKeyCiphertext().serialize()))
                                                                                        .setTimestamp(1)
                                                                                        .build()));
    assertThat(response.getStatus()).isEqualTo(400);
    verifyNoGroupWrites();
  }

  @Test
  void testAddMembersPendingAdminApproval_addingOtherUser() {
    final byte[] inviteLinkPassword = createGroupInviteLinkPassword();
    final Group group = this.group.toBuilder()
                                  .setAccessControl(this.group.getAccessControl().toBuilder().setAddFromInviteLink(AccessControl.AccessRequired.ADMINISTRATOR))
                                  .setInviteLinkPassword(ByteString.copyFrom(inviteLinkPassword))
                                  .removeMembers(1)
                                  .build();

    setupGroupsManagerBehaviors(group);

    GroupChange.Actions actions = GroupChange.Actions.newBuilder()
                                                         .setVersion(1)
                                                         .addAddMembersPendingAdminApproval(GroupChange.Actions.AddMemberPendingAdminApprovalAction.newBuilder()
                                                                                                                                                   .setAdded(MemberPendingAdminApproval.newBuilder()
                                                                                                                                                                                       .setPresentation(ByteString.copyFrom(validUserTwoPresentation.serialize()))
                                                                                                                                                                                       .build()))
                                                         .build();

    final Response response = resources.getJerseyTest()
                                       .target("/v1/groups/")
                                       .queryParam("inviteLinkPassword", Base64.encodeBase64URLSafeString(inviteLinkPassword))
                                       .request(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
                                       .header("Authorization", AuthHelper.getAuthHeader(groupSecretParams, AuthHelper.VALID_USER_THREE_AUTH_CREDENTIAL))
                                       .method("PATCH", Entity.entity(actions.toByteArray(), ProtocolBufferMediaType.APPLICATION_PROTOBUF));

    assertThat(response.getStatus()).isEqualTo(400);
    verifyNoGroupWrites();
  }

  @Test
  void testAddMembersPendingAdminApproval_addingTooManyUsers() {
    final byte[] inviteLinkPassword = createGroupInviteLinkPassword();
    final Group group = this.group.toBuilder()
                                  .setAccessControl(this.group.getAccessControl().toBuilder().setAddFromInviteLink(AccessControl.AccessRequired.ADMINISTRATOR))
                                  .setInviteLinkPassword(ByteString.copyFrom(inviteLinkPassword))
                                  .removeMembers(1)
                                  .build();

    setupGroupsManagerBehaviors(group);

    GroupChange.Actions actions = GroupChange.Actions.newBuilder()
                                                     .setVersion(1)
                                                     .addAddMembersPendingAdminApproval(GroupChange.Actions.AddMemberPendingAdminApprovalAction.newBuilder()
                                                                                                                                               .setAdded(MemberPendingAdminApproval.newBuilder()
                                                                                                                                                                                   .setPresentation(ByteString.copyFrom(validUserThreePresentation.serialize()))
                                                                                                                                                                                   .build()))
                                                     .addAddMembersPendingAdminApproval(GroupChange.Actions.AddMemberPendingAdminApprovalAction.newBuilder()
                                                                                                                                               .setAdded(MemberPendingAdminApproval.newBuilder()
                                                                                                                                                                                   .setPresentation(ByteString.copyFrom(validUserTwoPresentation.serialize()))
                                                                                                                                                                                   .build()))
                                                     .build();

    final Response response = resources.getJerseyTest()
                                       .target("/v1/groups/")
                                       .queryParam("inviteLinkPassword", Base64.encodeBase64URLSafeString(inviteLinkPassword))
                                       .request(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
                                       .header("Authorization", AuthHelper.getAuthHeader(groupSecretParams, AuthHelper.VALID_USER_THREE_AUTH_CREDENTIAL))
                                       .method("PATCH", Entity.entity(actions.toByteArray(), ProtocolBufferMediaType.APPLICATION_PROTOBUF));

    assertThat(response.getStatus()).isEqualTo(400);
    verifyNoGroupWrites();
  }

  @Test
  void testAddMembersPendingAdminApproval_alreadyMember() {
    final byte[] inviteLinkPassword = createGroupInviteLinkPassword();
    final Group group = this.group.toBuilder()
                                  .setAccessControl(this.group.getAccessControl().toBuilder().setAddFromInviteLink(AccessControl.AccessRequired.ADMINISTRATOR))
                                  .setInviteLinkPassword(ByteString.copyFrom(inviteLinkPassword))
                                  .build();

    setupGroupsManagerBehaviors(group);

    GroupChange.Actions actions = GroupChange.Actions.newBuilder()
                                                     .setVersion(1)
                                                     .addAddMembersPendingAdminApproval(GroupChange.Actions.AddMemberPendingAdminApprovalAction.newBuilder()
                                                                                                                                               .setAdded(MemberPendingAdminApproval.newBuilder()
                                                                                                                                                                                   .setPresentation(ByteString.copyFrom(validUserTwoPresentation.serialize()))
                                                                                                                                                                                   .build()))
                                                     .build();

    final Response response = resources.getJerseyTest()
                                       .target("/v1/groups/")
                                       .queryParam("inviteLinkPassword", Base64.encodeBase64URLSafeString(inviteLinkPassword))
                                       .request(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
                                       .header("Authorization", AuthHelper.getAuthHeader(groupSecretParams, AuthHelper.VALID_USER_TWO_AUTH_CREDENTIAL))
                                       .method("PATCH", Entity.entity(actions.toByteArray(), ProtocolBufferMediaType.APPLICATION_PROTOBUF));

    assertThat(response.getStatus()).isEqualTo(400);
    verifyNoGroupWrites();
  }

  @Test
  void testAddMembersPendingAdminApproval_alreadyMemberPendingProfileKey() {
    final byte[] inviteLinkPassword = createGroupInviteLinkPassword();
    final Group group = this.group.toBuilder()
                                  .setAccessControl(this.group.getAccessControl().toBuilder().setAddFromInviteLink(AccessControl.AccessRequired.ADMINISTRATOR))
                                  .setInviteLinkPassword(ByteString.copyFrom(inviteLinkPassword))
                                  .addMembersPendingProfileKey(MemberPendingProfileKey.newBuilder()
                                                                                      .setMember(this.group.getMembers(1))
                                                                                      .build())
                                  .removeMembers(1)
                                  .build();

    setupGroupsManagerBehaviors(group);

    GroupChange.Actions actions = GroupChange.Actions.newBuilder()
                                                     .setVersion(1)
                                                     .addAddMembersPendingAdminApproval(GroupChange.Actions.AddMemberPendingAdminApprovalAction.newBuilder()
                                                                                                                                               .setAdded(MemberPendingAdminApproval.newBuilder()
                                                                                                                                                                                   .setPresentation(ByteString.copyFrom(validUserTwoPresentation.serialize()))
                                                                                                                                                                                   .build()))
                                                     .build();

    final Response response = resources.getJerseyTest()
                                       .target("/v1/groups/")
                                       .queryParam("inviteLinkPassword", Base64.encodeBase64URLSafeString(inviteLinkPassword))
                                       .request(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
                                       .header("Authorization", AuthHelper.getAuthHeader(groupSecretParams, AuthHelper.VALID_USER_TWO_AUTH_CREDENTIAL))
                                       .method("PATCH", Entity.entity(actions.toByteArray(), ProtocolBufferMediaType.APPLICATION_PROTOBUF));

    assertThat(response.getStatus()).isEqualTo(400);
    verifyNoGroupWrites();
  }

  private Response setupForTestAddMembers(final byte[] inviteLinkPasswordQueryParam, final Function<Group.Builder, Group.Builder> groupBuilderFunction) {
    final Group group = groupBuilderFunction.apply(this.group.toBuilder()).build();
    setupGroupsManagerBehaviors(group);

    GroupChange.Actions actions = GroupChange.Actions.newBuilder()
                                                     .setVersion(1)
                                                     .addAddMembers(GroupChange.Actions.AddMemberAction.newBuilder()
                                                                                                       .setAdded(Member.newBuilder()
                                                                                                                       .setRole(Member.Role.DEFAULT)
                                                                                                                       .setPresentation(ByteString.copyFrom(validUserThreePresentation.serialize()))
                                                                                                                       .build())
                                                                                                       .build())
                                                     .build();

    return resources.getJerseyTest()
                    .target("/v1/groups/")
                    .queryParam("inviteLinkPassword", Base64.encodeBase64URLSafeString(inviteLinkPasswordQueryParam))
                    .request(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
                    .header("Authorization", AuthHelper.getAuthHeader(groupSecretParams, AuthHelper.VALID_USER_THREE_AUTH_CREDENTIAL))
                    .method("PATCH", Entity.entity(actions.toByteArray(), ProtocolBufferMediaType.APPLICATION_PROTOBUF));
  }

  @Test
  void testAddMembers() throws Exception {
    final byte[] inviteLinkPassword = createGroupInviteLinkPassword();
    final Function<Group.Builder, Group.Builder> groupBuilderFunction = builder -> builder.mergeAccessControl(AccessControl.newBuilder().setAddFromInviteLink(AccessControl.AccessRequired.ANY).build())
                                                                                          .setInviteLinkPassword(ByteString.copyFrom(inviteLinkPassword));
    final Response response = setupForTestAddMembers(inviteLinkPassword, groupBuilderFunction);

    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.hasEntity()).isTrue();
    assertThat(response.getMediaType().toString()).isEqualTo("application/x-protobuf");

    GroupChange signedChange = GroupChange.parseFrom(response.readEntity(InputStream.class).readAllBytes());

    ArgumentCaptor<Group>       captor       = ArgumentCaptor.forClass(Group.class      );
    ArgumentCaptor<GroupChange> changeCaptor = ArgumentCaptor.forClass(GroupChange.class);

    verify(groupsManager).updateGroup(eq(ByteString.copyFrom(groupPublicParams.getGroupIdentifier().serialize())), captor.capture());
    verify(groupsManager).appendChangeRecord(eq(ByteString.copyFrom(groupPublicParams.getGroupIdentifier().serialize())), eq(1), changeCaptor.capture(), any(Group.class));

    assertThat(captor.getValue().getVersion()).isEqualTo(1);
    assertThat(captor.getValue().getMembersList()).hasSize(3).last().matches(member -> member.getUserId().equals(ByteString.copyFrom(validUserThreePresentation.getUuidCiphertext().serialize())));

    assertThat(captor.getValue().toBuilder()
                     .setVersion(0)
                     .removeMembers(2)
                     .build())
            .isEqualTo(groupBuilderFunction.apply(group.toBuilder()).build());

    assertThat(signedChange).isEqualTo(changeCaptor.getValue());
    assertThat(GroupChange.Actions.parseFrom(signedChange.getActions()).getVersion()).isEqualTo(1);
    assertThat(GroupChange.Actions.parseFrom(signedChange.getActions()).getSourceUuid()).isEqualTo(ByteString.copyFrom(validUserThreePresentation.getUuidCiphertext().serialize()));
    assertThat(GroupChange.Actions.parseFrom(signedChange.getActions()).getAddMembersList()).hasSize(1).allMatch(GroupChange.Actions.AddMemberAction::getJoinFromInviteLink);

    AuthHelper.GROUPS_SERVER_KEY.getPublicParams().verifySignature(signedChange.getActions().toByteArray(),
                                                                   new NotarySignature(signedChange.getServerSignature().toByteArray()));
  }

  @Test
  void testAddMembers_wrongPassword() {
    final byte[] inviteLinkPassword = createGroupInviteLinkPassword();
    final byte[] wrongInviteLinkPassword = new byte[inviteLinkPassword.length];
    System.arraycopy(inviteLinkPassword, 0, wrongInviteLinkPassword, 0, wrongInviteLinkPassword.length);
    wrongInviteLinkPassword[wrongInviteLinkPassword.length - 1]++;
    final Response response = setupForTestAddMembers(
            wrongInviteLinkPassword,
            builder -> builder.mergeAccessControl(AccessControl.newBuilder().setAddFromInviteLink(AccessControl.AccessRequired.ANY).build())
                              .setInviteLinkPassword(ByteString.copyFrom(inviteLinkPassword)));
    assertThat(response.getStatus()).isEqualTo(403);
    verifyNoGroupWrites();
  }

  @Test
  void testAddMembers_noInviteLink() {
    final byte[] inviteLinkPassword = createGroupInviteLinkPassword();
    final Response response = setupForTestAddMembers(inviteLinkPassword, Function.identity());
    assertThat(response.getStatus()).isEqualTo(403);
    verifyNoGroupWrites();
  }

  @Test
  void testAddMembers_disabledInviteLink() {
    final byte[] inviteLinkPassword = createGroupInviteLinkPassword();
    final Response response = setupForTestAddMembers(
            inviteLinkPassword,
            builder -> builder.setAccessControl(this.group.getAccessControl().toBuilder().setAddFromInviteLink(AccessControl.AccessRequired.UNSATISFIABLE))
                              .setInviteLinkPassword(ByteString.copyFrom(inviteLinkPassword)));
    assertThat(response.getStatus()).isEqualTo(403);
    verifyNoGroupWrites();
  }

  @Test
  void testDeleteMembersPendingAdminApproval() throws Exception {
    final long timestamp = Instant.now().minus(Duration.ofHours(1)).toEpochMilli();
    final Group group = this.group.toBuilder()
                                  .addMembersPendingAdminApproval(MemberPendingAdminApproval.newBuilder()
                                                                                            .setProfileKey(ByteString.copyFrom(validUserThreePresentation.getProfileKeyCiphertext().serialize()))
                                                                                            .setUserId(ByteString.copyFrom(validUserThreePresentation.getUuidCiphertext().serialize()))
                                                                                            .setTimestamp(timestamp)
                                                                                            .build())
                                  .build();

    setupGroupsManagerBehaviors(group);

    GroupChange.Actions actions = GroupChange.Actions.newBuilder()
                                                     .setVersion(1)
                                                     .addDeleteMembersPendingAdminApproval(GroupChange.Actions.DeleteMemberPendingAdminApprovalAction.newBuilder()
                                                                                                                                                     .setDeletedUserId(ByteString.copyFrom(validUserThreePresentation.getUuidCiphertext().serialize()))
                                                                                                                                                     .build())
                                                     .build();

    final Response response = resources.getJerseyTest()
                                       .target("/v1/groups/")
                                       .request(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
                                       .header("Authorization", AuthHelper.getAuthHeader(groupSecretParams, AuthHelper.VALID_USER_AUTH_CREDENTIAL))
                                       .method("PATCH", Entity.entity(actions.toByteArray(), ProtocolBufferMediaType.APPLICATION_PROTOBUF));

    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.hasEntity()).isTrue();
    assertThat(response.getMediaType().toString()).isEqualTo("application/x-protobuf");

    GroupChange signedChange = GroupChange.parseFrom(response.readEntity(InputStream.class).readAllBytes());

    ArgumentCaptor<Group>       captor       = ArgumentCaptor.forClass(Group.class      );
    ArgumentCaptor<GroupChange> changeCaptor = ArgumentCaptor.forClass(GroupChange.class);

    verify(groupsManager).updateGroup(eq(ByteString.copyFrom(groupPublicParams.getGroupIdentifier().serialize())), captor.capture());
    verify(groupsManager).appendChangeRecord(eq(ByteString.copyFrom(groupPublicParams.getGroupIdentifier().serialize())), eq(1), changeCaptor.capture(), any(Group.class));

    assertThat(captor.getValue().getVersion()).isEqualTo(1);
    assertThat(captor.getValue().getMembersList()).hasSize(2);
    assertThat(captor.getValue().getMembersPendingAdminApprovalList()).isEmpty();

    assertThat(captor.getValue().toBuilder()
                     .setVersion(0)
                     .addMembersPendingAdminApproval(MemberPendingAdminApproval.newBuilder()
                                                                               .setProfileKey(ByteString.copyFrom(validUserThreePresentation.getProfileKeyCiphertext().serialize()))
                                                                               .setUserId(ByteString.copyFrom(validUserThreePresentation.getUuidCiphertext().serialize()))
                                                                               .setTimestamp(timestamp)
                                                                               .build())
                     .build())
            .isEqualTo(group);

    assertThat(signedChange).isEqualTo(changeCaptor.getValue());
    assertThat(GroupChange.Actions.parseFrom(signedChange.getActions()).getVersion()).isEqualTo(1);
    assertThat(GroupChange.Actions.parseFrom(signedChange.getActions()).getSourceUuid()).isEqualTo(ByteString.copyFrom(validUserPresentation.getUuidCiphertext().serialize()));

    AuthHelper.GROUPS_SERVER_KEY.getPublicParams().verifySignature(signedChange.getActions().toByteArray(),
                                                                   new NotarySignature(signedChange.getServerSignature().toByteArray()));
  }

  @Test
  void testDeleteMembersPendingAdminApproval_nonAdmin() {
    final long timestamp = Instant.now().minus(Duration.ofHours(1)).toEpochMilli();
    final Group group = this.group.toBuilder()
                                  .addMembersPendingAdminApproval(MemberPendingAdminApproval.newBuilder()
                                                                                            .setProfileKey(ByteString.copyFrom(validUserThreePresentation.getProfileKeyCiphertext().serialize()))
                                                                                            .setUserId(ByteString.copyFrom(validUserThreePresentation.getUuidCiphertext().serialize()))
                                                                                            .setTimestamp(timestamp)
                                                                                            .build())
                                  .build();

    setupGroupsManagerBehaviors(group);

    GroupChange.Actions actions = GroupChange.Actions.newBuilder()
                                                     .setVersion(1)
                                                     .addDeleteMembersPendingAdminApproval(GroupChange.Actions.DeleteMemberPendingAdminApprovalAction.newBuilder()
                                                                                                                                                     .setDeletedUserId(ByteString.copyFrom(validUserThreePresentation.getUuidCiphertext().serialize()))
                                                                                                                                                     .build())
                                                     .build();

    final Response response = resources.getJerseyTest()
                                       .target("/v1/groups/")
                                       .request(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
                                       .header("Authorization", AuthHelper.getAuthHeader(groupSecretParams, AuthHelper.VALID_USER_TWO_AUTH_CREDENTIAL))
                                       .method("PATCH", Entity.entity(actions.toByteArray(), ProtocolBufferMediaType.APPLICATION_PROTOBUF));

    assertThat(response.getStatus()).isEqualTo(403);
    verifyNoGroupWrites();
  }

  @Test
  void testDeleteMembersPendingAdminApproval_self() throws Exception {
    final long timestamp = Instant.now().minus(Duration.ofHours(1)).toEpochMilli();
    final Group group = this.group.toBuilder()
                                  .addMembersPendingAdminApproval(MemberPendingAdminApproval.newBuilder()
                                                                                            .setProfileKey(ByteString.copyFrom(validUserThreePresentation.getProfileKeyCiphertext().serialize()))
                                                                                            .setUserId(ByteString.copyFrom(validUserThreePresentation.getUuidCiphertext().serialize()))
                                                                                            .setTimestamp(timestamp)
                                                                                            .build())
                                  .build();

    setupGroupsManagerBehaviors(group);

    GroupChange.Actions actions = GroupChange.Actions.newBuilder()
                                                     .setVersion(1)
                                                     .addDeleteMembersPendingAdminApproval(GroupChange.Actions.DeleteMemberPendingAdminApprovalAction.newBuilder()
                                                                                                                                                     .setDeletedUserId(ByteString.copyFrom(validUserThreePresentation.getUuidCiphertext().serialize()))
                                                                                                                                                     .build())
                                                     .build();

    final Response response = resources.getJerseyTest()
                                       .target("/v1/groups/")
                                       .request(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
                                       .header("Authorization", AuthHelper.getAuthHeader(groupSecretParams, AuthHelper.VALID_USER_THREE_AUTH_CREDENTIAL))
                                       .method("PATCH", Entity.entity(actions.toByteArray(), ProtocolBufferMediaType.APPLICATION_PROTOBUF));

    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.hasEntity()).isTrue();
    assertThat(response.getMediaType().toString()).isEqualTo("application/x-protobuf");

    GroupChange signedChange = GroupChange.parseFrom(response.readEntity(InputStream.class).readAllBytes());

    ArgumentCaptor<Group>       captor       = ArgumentCaptor.forClass(Group.class      );
    ArgumentCaptor<GroupChange> changeCaptor = ArgumentCaptor.forClass(GroupChange.class);

    verify(groupsManager).updateGroup(eq(ByteString.copyFrom(groupPublicParams.getGroupIdentifier().serialize())), captor.capture());
    verify(groupsManager).appendChangeRecord(eq(ByteString.copyFrom(groupPublicParams.getGroupIdentifier().serialize())), eq(1), changeCaptor.capture(), any(Group.class));

    assertThat(captor.getValue().getVersion()).isEqualTo(1);
    assertThat(captor.getValue().getMembersList()).hasSize(2);
    assertThat(captor.getValue().getMembersPendingAdminApprovalList()).isEmpty();

    assertThat(captor.getValue().toBuilder()
                     .setVersion(0)
                     .addMembersPendingAdminApproval(MemberPendingAdminApproval.newBuilder()
                                                                               .setProfileKey(ByteString.copyFrom(validUserThreePresentation.getProfileKeyCiphertext().serialize()))
                                                                               .setUserId(ByteString.copyFrom(validUserThreePresentation.getUuidCiphertext().serialize()))
                                                                               .setTimestamp(timestamp)
                                                                               .build())
                     .build())
            .isEqualTo(group);

    assertThat(signedChange).isEqualTo(changeCaptor.getValue());
    assertThat(GroupChange.Actions.parseFrom(signedChange.getActions()).getVersion()).isEqualTo(1);
    assertThat(GroupChange.Actions.parseFrom(signedChange.getActions()).getSourceUuid()).isEqualTo(ByteString.copyFrom(validUserThreePresentation.getUuidCiphertext().serialize()));

    AuthHelper.GROUPS_SERVER_KEY.getPublicParams().verifySignature(signedChange.getActions().toByteArray(),
                                                                   new NotarySignature(signedChange.getServerSignature().toByteArray()));
  }

  @Test
  void testPromoteMembersPendingAdminApproval() throws Exception {
    final long timestamp = Instant.now().minus(Duration.ofHours(1)).toEpochMilli();
    final Group group = this.group.toBuilder()
                                  .addMembersPendingAdminApproval(MemberPendingAdminApproval.newBuilder()
                                                                                            .setProfileKey(ByteString.copyFrom(validUserThreePresentation.getProfileKeyCiphertext().serialize()))
                                                                                            .setUserId(ByteString.copyFrom(validUserThreePresentation.getUuidCiphertext().serialize()))
                                                                                            .setTimestamp(timestamp)
                                                                                            .build())
                                  .build();

    setupGroupsManagerBehaviors(group);

    GroupChange.Actions actions = GroupChange.Actions.newBuilder()
                                                     .setVersion(1)
                                                     .addPromoteMembersPendingAdminApproval(GroupChange.Actions.PromoteMemberPendingAdminApprovalAction.newBuilder()
                                                                                                                                                       .setUserId(ByteString.copyFrom(validUserThreePresentation.getUuidCiphertext().serialize()))
                                                                                                                                                       .setRole(Member.Role.DEFAULT)
                                                                                                                                                       .build())
                                                     .build();

    final Response response = resources.getJerseyTest()
                                       .target("/v1/groups/")
                                       .request(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
                                       .header("Authorization", AuthHelper.getAuthHeader(groupSecretParams, AuthHelper.VALID_USER_AUTH_CREDENTIAL))
                                       .method("PATCH", Entity.entity(actions.toByteArray(), ProtocolBufferMediaType.APPLICATION_PROTOBUF));

    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.hasEntity()).isTrue();
    assertThat(response.getMediaType().toString()).isEqualTo("application/x-protobuf");

    GroupChange signedChange = GroupChange.parseFrom(response.readEntity(InputStream.class).readAllBytes());

    ArgumentCaptor<Group>       captor       = ArgumentCaptor.forClass(Group.class      );
    ArgumentCaptor<GroupChange> changeCaptor = ArgumentCaptor.forClass(GroupChange.class);

    verify(groupsManager).updateGroup(eq(ByteString.copyFrom(groupPublicParams.getGroupIdentifier().serialize())), captor.capture());
    verify(groupsManager).appendChangeRecord(eq(ByteString.copyFrom(groupPublicParams.getGroupIdentifier().serialize())), eq(1), changeCaptor.capture(), any(Group.class));

    assertThat(captor.getValue().getVersion()).isEqualTo(1);
    assertThat(captor.getValue().getMembersList()).hasSize(3).last().matches(member -> member.getUserId().equals(ByteString.copyFrom(validUserThreePresentation.getUuidCiphertext().serialize())) &&
                                                                                       member.getProfileKey().equals(ByteString.copyFrom(validUserThreePresentation.getProfileKeyCiphertext().serialize())) &&
                                                                                       member.getRole() == Member.Role.DEFAULT);
    assertThat(captor.getValue().getMembersPendingAdminApprovalList()).isEmpty();

    assertThat(captor.getValue().toBuilder()
                     .setVersion(0)
                     .removeMembers(2)
                     .addMembersPendingAdminApproval(MemberPendingAdminApproval.newBuilder()
                                                                               .setProfileKey(ByteString.copyFrom(validUserThreePresentation.getProfileKeyCiphertext().serialize()))
                                                                               .setUserId(ByteString.copyFrom(validUserThreePresentation.getUuidCiphertext().serialize()))
                                                                               .setTimestamp(timestamp)
                                                                               .build())
                     .build())
            .isEqualTo(group);

    assertThat(signedChange).isEqualTo(changeCaptor.getValue());
    assertThat(GroupChange.Actions.parseFrom(signedChange.getActions()).getVersion()).isEqualTo(1);
    assertThat(GroupChange.Actions.parseFrom(signedChange.getActions()).getSourceUuid()).isEqualTo(ByteString.copyFrom(validUserPresentation.getUuidCiphertext().serialize()));

    AuthHelper.GROUPS_SERVER_KEY.getPublicParams().verifySignature(signedChange.getActions().toByteArray(),
                                                                   new NotarySignature(signedChange.getServerSignature().toByteArray()));
  }

  @Test
  void testPromoteMembersPendingAdminApproval_nonAdmin() {
    final long timestamp = Instant.now().minus(Duration.ofHours(1)).toEpochMilli();
    final Group group = this.group.toBuilder()
                                  .addMembersPendingAdminApproval(MemberPendingAdminApproval.newBuilder()
                                                                                            .setProfileKey(ByteString.copyFrom(validUserThreePresentation.getProfileKeyCiphertext().serialize()))
                                                                                            .setUserId(ByteString.copyFrom(validUserThreePresentation.getUuidCiphertext().serialize()))
                                                                                            .setTimestamp(timestamp)
                                                                                            .build())
                                  .build();

    setupGroupsManagerBehaviors(group);

    GroupChange.Actions actions = GroupChange.Actions.newBuilder()
                                                     .setVersion(1)
                                                     .addPromoteMembersPendingAdminApproval(GroupChange.Actions.PromoteMemberPendingAdminApprovalAction.newBuilder()
                                                                                                                                                       .setUserId(ByteString.copyFrom(validUserThreePresentation.getUuidCiphertext().serialize()))
                                                                                                                                                       .setRole(Member.Role.DEFAULT)
                                                                                                                                                       .build())
                                                     .build();

    final Response response = resources.getJerseyTest()
                                       .target("/v1/groups/")
                                       .request(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
                                       .header("Authorization", AuthHelper.getAuthHeader(groupSecretParams, AuthHelper.VALID_USER_TWO_AUTH_CREDENTIAL))
                                       .method("PATCH", Entity.entity(actions.toByteArray(), ProtocolBufferMediaType.APPLICATION_PROTOBUF));

    assertThat(response.getStatus()).isEqualTo(403);
    verifyNoGroupWrites();
  }

  @Test
  void testPromoteMembersPendingAdminApproval_self() {
    final long timestamp = Instant.now().minus(Duration.ofHours(1)).toEpochMilli();
    final Group group = this.group.toBuilder()
                                  .addMembersPendingAdminApproval(MemberPendingAdminApproval.newBuilder()
                                                                                            .setProfileKey(ByteString.copyFrom(validUserThreePresentation.getProfileKeyCiphertext().serialize()))
                                                                                            .setUserId(ByteString.copyFrom(validUserThreePresentation.getUuidCiphertext().serialize()))
                                                                                            .setTimestamp(timestamp)
                                                                                            .build())
                                  .build();

    setupGroupsManagerBehaviors(group);

    GroupChange.Actions actions = GroupChange.Actions.newBuilder()
                                                     .setVersion(1)
                                                     .addPromoteMembersPendingAdminApproval(GroupChange.Actions.PromoteMemberPendingAdminApprovalAction.newBuilder()
                                                                                                                                                       .setUserId(ByteString.copyFrom(validUserThreePresentation.getUuidCiphertext().serialize()))
                                                                                                                                                       .setRole(Member.Role.DEFAULT)
                                                                                                                                                       .build())
                                                     .build();

    final Response response = resources.getJerseyTest()
                                       .target("/v1/groups/")
                                       .request(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
                                       .header("Authorization", AuthHelper.getAuthHeader(groupSecretParams, AuthHelper.VALID_USER_THREE_AUTH_CREDENTIAL))
                                       .method("PATCH", Entity.entity(actions.toByteArray(), ProtocolBufferMediaType.APPLICATION_PROTOBUF));

    assertThat(response.getStatus()).isEqualTo(403);
    verifyNoGroupWrites();
  }
}
