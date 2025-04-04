package org.signal.storageservice.controllers;

import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.core.Response;
import com.google.protobuf.ByteString;
import org.junit.jupiter.api.Test;
import org.signal.storageservice.providers.ProtocolBufferMediaType;
import org.signal.storageservice.storage.protos.groups.Group;
import org.signal.storageservice.storage.protos.groups.GroupChange;
import org.signal.storageservice.storage.protos.groups.Member;
import org.signal.storageservice.storage.protos.groups.MemberPendingProfileKey;
import org.signal.storageservice.util.AuthHelper;

class GroupsControllerPhoneNumberPrivacyTest extends BaseGroupsControllerTest {

  @Test
  void testRejectInvitationFromPni() throws Exception {
    Group.Builder groupBuilder = Group.newBuilder(this.group)
        .addMembersPendingProfileKey(MemberPendingProfileKey.newBuilder()
            .setMember(Member.newBuilder()
                .setUserId(validUserThreePniId)
                .setRole(Member.Role.DEFAULT)
                .setJoinedAtVersion(0)
                .build())
            .setAddedByUserId(validUserId)
            .setTimestamp(clock.millis())
            .build());

    setupGroupsManagerBehaviors(groupBuilder.build());

    GroupChange.Actions.Builder actionsBuilder = GroupChange.Actions.newBuilder()
        .setVersion(1)
        .addDeleteMembersPendingProfileKey(GroupChange.Actions.DeleteMemberPendingProfileKeyAction.newBuilder()
            .setDeletedUserId(validUserThreePniId)
            .build());

    groupBuilder.clearMembersPendingProfileKey().setVersion(1);

    try (Response response = resources.getJerseyTest()
        .target("/v1/groups/")
        .request(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
        .header("Authorization", AuthHelper.getAuthHeader(groupSecretParams, AuthHelper.VALID_USER_THREE_AUTH_CREDENTIAL))
        .method("PATCH", Entity.entity(actionsBuilder.build().toByteArray(), ProtocolBufferMediaType.APPLICATION_PROTOBUF))) {

      actionsBuilder.setGroupId(ByteString.copyFrom(groupPublicParams.getGroupIdentifier().serialize()));
      verifyGroupModification(groupBuilder, actionsBuilder, 0, response, validUserThreePniId);
    }
  }
}
