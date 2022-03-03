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
import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Response;
import org.junit.Test;
import org.signal.storageservice.providers.ProtocolBufferMediaType;
import org.signal.storageservice.storage.protos.groups.AccessControl;
import org.signal.storageservice.storage.protos.groups.Group;
import org.signal.storageservice.storage.protos.groups.GroupChange;
import org.signal.storageservice.storage.protos.groups.GroupChanges.GroupChangeState;
import org.signal.storageservice.util.AuthHelper;

public class GroupsControllerBannedMembersTest extends BaseGroupsControllerTest {
  @Test
  public void testGetGroupJoinInfoWhenBanned() {
    final byte[] inviteLinkPassword = new byte[16];
    new SecureRandom().nextBytes(inviteLinkPassword);
    final String inviteLinkPasswordString = Base64.getUrlEncoder().encodeToString(inviteLinkPassword);

    final Group.Builder groupBuilder = group.toBuilder();

    setMockGroupState(groupBuilder);
    Response response = getGroupJoinInfoWithPassword(inviteLinkPasswordString);
    assertThat(response.getStatus()).isEqualTo(403);
    assertThat(response.hasEntity()).isFalse();
    assertThat(response.getStringHeaders()).doesNotContainKey("x-signal-forbidden-reason");

    groupBuilder.setInviteLinkPassword(ByteString.copyFrom(inviteLinkPassword));

    setMockGroupState(groupBuilder);
    response = getGroupJoinInfoWithPassword(inviteLinkPasswordString);
    assertThat(response.getStatus()).isEqualTo(403);
    assertThat(response.hasEntity()).isFalse();
    assertThat(response.getStringHeaders()).doesNotContainKey("x-signal-forbidden-reason");

    groupBuilder.getAccessControlBuilder().setAddFromInviteLink(AccessControl.AccessRequired.ANY);

    setMockGroupState(groupBuilder);
    response = getGroupJoinInfoWithPassword(inviteLinkPasswordString);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.hasEntity()).isTrue();
    assertThat(response.getStringHeaders()).doesNotContainKey("x-signal-forbidden-reason");

    groupBuilder.addMembersBannedBuilder().setUserId(ByteString.copyFrom(validUserFourPresentation.getUuidCiphertext().serialize()));

    setMockGroupState(groupBuilder);
    response = getGroupJoinInfoWithPassword(inviteLinkPasswordString);
    assertThat(response.getStatus()).isEqualTo(403);
    assertThat(response.hasEntity()).isFalse();
    assertThat(response.getStringHeaders()).containsEntry("x-signal-forbidden-reason", List.of("banned"));
  }

  @Test
  public void testGetGroupLogsWhenBanned() {
    final Group.Builder groupBuilder = group.toBuilder();

    setMockGroupState(groupBuilder);
    when(groupsManager.getChangeRecords(eq(ByteString.copyFrom(groupPublicParams.getGroupIdentifier().serialize())), isA(Group.class), any(), anyBoolean(), anyBoolean(), anyInt(), anyInt()))
        .thenReturn(CompletableFuture.completedFuture(List.of(GroupChangeState.newBuilder().setGroupState(groupBuilder).build())));
    Response response = getGroupLogs(0);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.hasEntity()).isTrue();

    groupBuilder.addMembersBannedBuilder().setUserId(groupBuilder.getMembers(1).getUserId());
    groupBuilder.removeMembers(1);

    setMockGroupState(groupBuilder);
    when(groupsManager.getChangeRecords(eq(ByteString.copyFrom(groupPublicParams.getGroupIdentifier().serialize())), isA(Group.class), any(), anyBoolean(), anyBoolean(), anyInt(), anyInt()))
        .thenReturn(CompletableFuture.completedFuture(List.of(GroupChangeState.newBuilder().setGroupState(groupBuilder).build())));
    response = getGroupLogs(0);
    assertThat(response.getStatus()).isEqualTo(403);
    assertThat(response.hasEntity()).isFalse();
  }

  @Test
  public void testGetGroupWhenBanned() {
    final Group.Builder groupBuilder = group.toBuilder();

    setMockGroupState(groupBuilder);
    Response response = getGroup();
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.hasEntity()).isTrue();

    groupBuilder.addMembersBannedBuilder().setUserId(groupBuilder.getMembers(0).getUserId());
    groupBuilder.removeMembers(0);

    setMockGroupState(groupBuilder);
    response = getGroup();
    assertThat(response.getStatus()).isEqualTo(403);
    assertThat(response.hasEntity()).isFalse();
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

    Response response = createGroup(groupBuilder);
    assertThat(response.getStatus()).isEqualTo(200);

    groupBuilder.addMembersBannedBuilder().setUserId(ByteString.copyFrom(validUserFourPresentation.getUuidCiphertext().serialize()));

    response = createGroup(groupBuilder);
    assertThat(response.getStatus()).isEqualTo(400);
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
}
