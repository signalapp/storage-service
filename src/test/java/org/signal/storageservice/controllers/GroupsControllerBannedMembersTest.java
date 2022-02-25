package org.signal.storageservice.controllers;

import static org.assertj.core.api.Assertions.assertThat;

import com.google.protobuf.ByteString;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.List;
import javax.ws.rs.core.Response;
import org.junit.Test;
import org.signal.storageservice.providers.ProtocolBufferMediaType;
import org.signal.storageservice.storage.protos.groups.AccessControl;
import org.signal.storageservice.storage.protos.groups.Group;
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

  private Response getGroupJoinInfoWithPassword(String inviteLinkPasswordString) {
    return resources.getJerseyTest()
        .target("/v1/groups/join/" + inviteLinkPasswordString)
        .request(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
        .header("Authorization", AuthHelper.getAuthHeader(groupSecretParams, AuthHelper.VALID_USER_FOUR_AUTH_CREDENTIAL))
        .get();
  }
}
