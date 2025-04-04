package org.signal.storageservice.controllers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.when;

import com.google.protobuf.ByteString;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.Test;
import org.signal.storageservice.providers.ProtocolBufferMediaType;
import org.signal.storageservice.storage.protos.groups.AccessControl;
import org.signal.storageservice.storage.protos.groups.AccessControl.AccessRequired;
import org.signal.storageservice.storage.protos.groups.Group;
import org.signal.storageservice.storage.protos.groups.GroupChange;
import org.signal.storageservice.storage.protos.groups.GroupChanges.GroupChangeState;
import org.signal.storageservice.storage.protos.groups.Member.Role;
import org.signal.storageservice.storage.protos.groups.MemberBanned;
import org.signal.storageservice.util.AuthHelper;
import org.signal.libsignal.zkgroup.auth.AuthCredentialWithPni;

class GroupsControllerBannedMembersTest extends BaseGroupsControllerTest {

  @Test
  public void testGetGroupJoinInfoWhenBanned() {
    final byte[] inviteLinkPassword = new byte[16];
    new SecureRandom().nextBytes(inviteLinkPassword);
    final String inviteLinkPasswordString = Base64.getUrlEncoder().encodeToString(inviteLinkPassword);

    final Group.Builder groupBuilder = group.toBuilder();
    setMockGroupState(groupBuilder);

    try (Response response = getGroupJoinInfoWithPassword(inviteLinkPasswordString)) {
      assertThat(response.getStatus()).isEqualTo(403);
      assertThat(response.hasEntity()).isFalse();
      assertThat(response.getStringHeaders()).doesNotContainKey("x-signal-forbidden-reason");
    }

    groupBuilder.setInviteLinkPassword(ByteString.copyFrom(inviteLinkPassword));
    setMockGroupState(groupBuilder);

    try (Response response = getGroupJoinInfoWithPassword(inviteLinkPasswordString)) {
      assertThat(response.getStatus()).isEqualTo(403);
      assertThat(response.hasEntity()).isFalse();
      assertThat(response.getStringHeaders()).doesNotContainKey("x-signal-forbidden-reason");
    }

    groupBuilder.getAccessControlBuilder().setAddFromInviteLink(AccessControl.AccessRequired.ANY);
    setMockGroupState(groupBuilder);

    try (Response response = getGroupJoinInfoWithPassword(inviteLinkPasswordString)) {
      assertThat(response.getStatus()).isEqualTo(200);
      assertThat(response.hasEntity()).isTrue();
      assertThat(response.getStringHeaders()).doesNotContainKey("x-signal-forbidden-reason");
    }

    groupBuilder.addMembersBannedBuilder().setUserId(ByteString.copyFrom(validUserFourPresentation.getUuidCiphertext().serialize())).setTimestamp(clock.millis());
    setMockGroupState(groupBuilder);

    try (Response response = getGroupJoinInfoWithPassword(inviteLinkPasswordString)) {
      assertThat(response.getStatus()).isEqualTo(403);
      assertThat(response.hasEntity()).isFalse();
      assertThat(response.getStringHeaders()).containsEntry("x-signal-forbidden-reason", List.of("banned"));
    }
  }

  @Test
  public void testGetGroupLogsWhenBanned() {
    final Group.Builder groupBuilder = group.toBuilder();

    setMockGroupState(groupBuilder);
    when(groupsManager.getChangeRecords(eq(ByteString.copyFrom(groupPublicParams.getGroupIdentifier().serialize())), isA(Group.class), any(), anyBoolean(), anyBoolean(), anyInt(), anyInt()))
        .thenReturn(CompletableFuture.completedFuture(List.of(GroupChangeState.newBuilder().setGroupState(groupBuilder).build())));

    try (Response response = getGroupLogs(0)){
      assertThat(response.getStatus()).isEqualTo(200);
      assertThat(response.hasEntity()).isTrue();
    }

    groupBuilder.addMembersBannedBuilder().setUserId(groupBuilder.getMembers(1).getUserId()).setTimestamp(clock.millis());
    groupBuilder.removeMembers(1);

    setMockGroupState(groupBuilder);
    when(groupsManager.getChangeRecords(eq(ByteString.copyFrom(groupPublicParams.getGroupIdentifier().serialize())), isA(Group.class), any(), anyBoolean(), anyBoolean(), anyInt(), anyInt()))
        .thenReturn(CompletableFuture.completedFuture(List.of(GroupChangeState.newBuilder().setGroupState(groupBuilder).build())));

    try (Response response = getGroupLogs(0)) {
      assertThat(response.getStatus()).isEqualTo(403);
      assertThat(response.hasEntity()).isFalse();
    }
  }

  @Test
  public void testGetGroupWhenBanned() {
    final Group.Builder groupBuilder = group.toBuilder();

    setMockGroupState(groupBuilder);

    try (Response  response = getGroup()) {
      assertThat(response.getStatus()).isEqualTo(200);
      assertThat(response.hasEntity()).isTrue();
    }

    groupBuilder.addMembersBannedBuilder().setUserId(groupBuilder.getMembers(0).getUserId()).setTimestamp(clock.millis());
    groupBuilder.removeMembers(0);
    setMockGroupState(groupBuilder);

    try (Response response = getGroup()) {
      assertThat(response.getStatus()).isEqualTo(403);
      assertThat(response.hasEntity()).isFalse();
    }
  }

  @Test
  public void testCreateGroupWithBannedMembers() {
    final Group.Builder groupBuilder = group.toBuilder();

    when(groupsManager.createGroup(eq(ByteString.copyFrom(groupPublicParams.getGroupIdentifier().serialize())), isA(Group.class)))
        .thenReturn(CompletableFuture.completedFuture(true));
    when(groupsManager.appendChangeRecord(eq(ByteString.copyFrom(groupPublicParams.getGroupIdentifier().serialize())), eq(0), isA(GroupChange.class), isA(Group.class)))
        .thenReturn(CompletableFuture.completedFuture(true));

    groupBuilder.getMembersBuilder(0).setPresentation(ByteString.copyFrom(validUserPresentation.serialize()));
    groupBuilder.getMembersBuilder(1).setPresentation(ByteString.copyFrom(validUserTwoPresentation.serialize()));

    try (Response response = createGroup(groupBuilder)) {
      assertThat(response.getStatus()).isEqualTo(200);
    }

    groupBuilder.addMembersBannedBuilder().setUserId(ByteString.copyFrom(validUserFourPresentation.getUuidCiphertext().serialize())).setTimestamp(clock.millis());

    try (Response response = createGroup(groupBuilder)) {
      assertThat(response.getStatus()).isEqualTo(400);
    }
  }

  @Test
  public void testModifyGroupBanMember() throws Exception {
    final Group.Builder groupBuilder = group.toBuilder();
    final GroupChange.Actions.Builder actionsBuilder = GroupChange.Actions.newBuilder();

    actionsBuilder.addAddMembersBannedBuilder().getAddedBuilder().setUserId(validUserThreeId);
    actionsBuilder.setVersion(1);

    setMockGroupState(groupBuilder);
    setupGroupsManagerForWrites();

    try (Response response = modifyGroup(AuthHelper.VALID_USER_AUTH_CREDENTIAL, actionsBuilder)) {
      actionsBuilder.setGroupId(ByteString.copyFrom(groupPublicParams.getGroupIdentifier().serialize()));
      actionsBuilder.getAddMembersBannedBuilder(0).getAddedBuilder().setTimestamp(clock.millis());
      groupBuilder.setVersion(1).addMembersBannedBuilder().setUserId(validUserThreeId).setTimestamp(clock.millis());
      assertThat(response.getStatus()).isEqualTo(200);
      verifyGroupModification(groupBuilder, actionsBuilder, 4, response, validUserId);
    }
  }

  @Test
  public void testModifyGroupBanMemberAsNonAdmin() {
    final Group.Builder groupBuilder = group.toBuilder();
    final GroupChange.Actions.Builder actionsBuilder = GroupChange.Actions.newBuilder();

    actionsBuilder.addAddMembersBannedBuilder().getAddedBuilder().setUserId(validUserThreeId);
    actionsBuilder.setVersion(1);

    setMockGroupState(groupBuilder);
    setupGroupsManagerForWrites();

    try (Response response = modifyGroup(AuthHelper.VALID_USER_TWO_AUTH_CREDENTIAL, actionsBuilder)) {
      assertThat(response.getStatus()).isEqualTo(403);
      verifyNoGroupWrites();
    }
  }

  @Test
  public void testModifyGroupUnbanMember() throws Exception {
    final Group.Builder groupBuilder = group.toBuilder();
    final GroupChange.Actions.Builder actionsBuilder = GroupChange.Actions.newBuilder();

    groupBuilder.addMembersBannedBuilder().setUserId(validUserThreeId).setTimestamp(clock.millis());
    actionsBuilder.addDeleteMembersBannedBuilder().setDeletedUserId(validUserThreeId);
    actionsBuilder.setVersion(1);

    setMockGroupState(groupBuilder);
    setupGroupsManagerForWrites();

    try (Response response = modifyGroup(AuthHelper.VALID_USER_AUTH_CREDENTIAL, actionsBuilder)) {
      actionsBuilder.setGroupId(ByteString.copyFrom(groupPublicParams.getGroupIdentifier().serialize()));
      groupBuilder.setVersion(1).clearMembersBanned();
      assertThat(response.getStatus()).isEqualTo(200);
      verifyGroupModification(groupBuilder, actionsBuilder, 4, response, validUserId);
    }
  }

  @Test
  public void testModifyGroupUnbanMemberAsNonAdmin() {
    final Group.Builder groupBuilder = group.toBuilder();
    final GroupChange.Actions.Builder actionsBuilder = GroupChange.Actions.newBuilder();

    groupBuilder.getAccessControlBuilder().setMembers(AccessRequired.ADMINISTRATOR);
    groupBuilder.addMembersBannedBuilder().setUserId(validUserThreeId).setTimestamp(clock.millis());
    actionsBuilder.addDeleteMembersBannedBuilder().setDeletedUserId(validUserThreeId);
    actionsBuilder.setVersion(1);

    setMockGroupState(groupBuilder);
    setupGroupsManagerForWrites();

    try (Response response = modifyGroup(AuthHelper.VALID_USER_TWO_AUTH_CREDENTIAL, actionsBuilder)) {
      assertThat(response.getStatus()).isEqualTo(403);
      verifyNoGroupWrites();
    }
  }

  @Test
  public void testModifyGroupUnbanMemberAsNonAdminWithOpenGroup() throws Exception {
    final Group.Builder groupBuilder = group.toBuilder();
    final GroupChange.Actions.Builder actionsBuilder = GroupChange.Actions.newBuilder();

    groupBuilder.addMembersBannedBuilder().setUserId(validUserThreeId).setTimestamp(clock.millis());
    actionsBuilder.addDeleteMembersBannedBuilder().setDeletedUserId(validUserThreeId);
    actionsBuilder.setVersion(1);

    setMockGroupState(groupBuilder);
    setupGroupsManagerForWrites();

    try (Response response = modifyGroup(AuthHelper.VALID_USER_TWO_AUTH_CREDENTIAL, actionsBuilder)) {
      actionsBuilder.setGroupId(ByteString.copyFrom(groupPublicParams.getGroupIdentifier().serialize()));
      groupBuilder.setVersion(1).clearMembersBanned();
      assertThat(response.getStatus()).isEqualTo(200);
      verifyGroupModification(groupBuilder, actionsBuilder, 4, response, validUserTwoId);
    }
  }

  @Test
  public void testModifyGroupBanMemberWithoutRemoval() {
    final Group.Builder groupBuilder = group.toBuilder();
    final GroupChange.Actions.Builder actionsBuilder = GroupChange.Actions.newBuilder();

    actionsBuilder.addAddMembersBannedBuilder().getAddedBuilder().setUserId(validUserTwoId);
    actionsBuilder.setVersion(1);

    setMockGroupState(groupBuilder);
    setupGroupsManagerForWrites();

    try (Response response = modifyGroup(AuthHelper.VALID_USER_AUTH_CREDENTIAL, actionsBuilder)) {
      assertThat(response.getStatus()).isEqualTo(400);
      verifyNoGroupWrites();
    }
  }

  @Test
  public void testModifyGroupBanMemberPendingProfileKeyWithoutRemoval() {
    final Group.Builder groupBuilder = group.toBuilder();
    final GroupChange.Actions.Builder actionsBuilder = GroupChange.Actions.newBuilder();

    groupBuilder.addMembersPendingProfileKeyBuilder().getMemberBuilder().setUserId(validUserThreeId).setRole(Role.DEFAULT);
    actionsBuilder.addAddMembersBannedBuilder().getAddedBuilder().setUserId(validUserThreeId);
    actionsBuilder.setVersion(1);

    setMockGroupState(groupBuilder);
    setupGroupsManagerForWrites();

    try (Response response = modifyGroup(AuthHelper.VALID_USER_AUTH_CREDENTIAL, actionsBuilder)) {
      assertThat(response.getStatus()).isEqualTo(400);
      verifyNoGroupWrites();
    }
  }

  @Test
  public void testModifyGroupBanMemberPendingAdminApprovalWithoutRemoval() {
    final Group.Builder groupBuilder = group.toBuilder();
    final GroupChange.Actions.Builder actionsBuilder = GroupChange.Actions.newBuilder();

    groupBuilder.addMembersPendingAdminApprovalBuilder().setUserId(validUserThreeId).setProfileKey(ByteString.copyFrom(validUserThreePresentation.getProfileKeyCiphertext().serialize()));
    actionsBuilder.addAddMembersBannedBuilder().getAddedBuilder().setUserId(validUserThreeId);
    actionsBuilder.setVersion(1);

    setMockGroupState(groupBuilder);
    setupGroupsManagerForWrites();

    try (Response response = modifyGroup(AuthHelper.VALID_USER_AUTH_CREDENTIAL, actionsBuilder)) {
      assertThat(response.getStatus()).isEqualTo(400);
      verifyNoGroupWrites();
    }
  }

  @Test
  public void testModifyGroupBanMemberAddAndDeleteInSameChange() {
    final Group.Builder groupBuilder = group.toBuilder();

    // for the DeleteMemberBannedAction to pass validation, the user needs to be currently banned
    groupBuilder.addMembersBannedBuilder().setUserId(validUserThreeId);
    setMockGroupState(groupBuilder);

    final GroupChange.Actions.Builder actionsBuilder = GroupChange.Actions.newBuilder();
    actionsBuilder.addAddMembersBannedBuilder().setAdded(MemberBanned.newBuilder().setUserId(validUserThreeId).build());
    actionsBuilder.addDeleteMembersBannedBuilder().setDeletedUserId(validUserThreeId);
    actionsBuilder.setVersion(1);

    setupGroupsManagerForWrites();

    try (Response response = modifyGroup(AuthHelper.VALID_USER_AUTH_CREDENTIAL, actionsBuilder)) {
      actionsBuilder.setGroupId(ByteString.copyFrom(groupPublicParams.getGroupIdentifier().serialize()));
      assertThat(response.getStatus()).isEqualTo(400);
      verifyNoGroupWrites();
    }
  }

  private Response createGroup(Group.Builder groupBuilder) {
    return resources.getJerseyTest()
        .target("/v1/groups/")
        .request(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
        .header("Authorization", AuthHelper.getAuthHeader(groupSecretParams, AuthHelper.VALID_USER_AUTH_CREDENTIAL))
        .put(Entity.entity(groupBuilder.build().toByteArray(), ProtocolBufferMediaType.APPLICATION_PROTOBUF));
  }

  private Response getGroupLogs(int fromVersion) {
    return resources.getJerseyTest()
        .target("/v1/groups/logs/" + fromVersion)
        .request(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
        .header("Authorization", AuthHelper.getAuthHeader(groupSecretParams, AuthHelper.VALID_USER_TWO_AUTH_CREDENTIAL))
        .get();
  }

  private Response getGroup() {
    return resources.getJerseyTest()
        .target("/v1/groups")
        .request(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
        .header("Authorization", AuthHelper.getAuthHeader(groupSecretParams, AuthHelper.VALID_USER_AUTH_CREDENTIAL))
        .get();
  }

  private Response getGroupJoinInfoWithPassword(String inviteLinkPasswordString) {
    return resources.getJerseyTest()
        .target("/v1/groups/join/" + inviteLinkPasswordString)
        .request(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
        .header("Authorization", AuthHelper.getAuthHeader(groupSecretParams, AuthHelper.VALID_USER_FOUR_AUTH_CREDENTIAL))
        .get();
  }

  private Response modifyGroup(AuthCredentialWithPni authCredential, GroupChange.Actions.Builder groupChangeActionsBuilder) {
    return resources.getJerseyTest()
        .target("/v1/groups")
        .request(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
        .header("Authorization", AuthHelper.getAuthHeader(groupSecretParams, authCredential))
        .method("PATCH", Entity.entity(
            groupChangeActionsBuilder.build().toByteArray(), ProtocolBufferMediaType.APPLICATION_PROTOBUF));
  }
}
