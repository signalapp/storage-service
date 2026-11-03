/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.groups;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

import com.google.protobuf.ByteString;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.signal.storageservice.storage.protos.groups.Group;
import org.signal.storageservice.storage.protos.groups.GroupChange.Actions.PromoteMemberPendingProfileKeyAction;
import org.signal.storageservice.storage.protos.groups.Member;
import org.signal.storageservice.storage.protos.groups.MemberPendingProfileKey;

class GroupChangeApplicatorTest {

  private final GroupChangeApplicator groupChangeApplicator = new GroupChangeApplicator(mock(GroupValidator.class));

  @Test
  void promoteMembersPendingProfileKeyWithRepeatedFieldBuilderInstalled() {
    final ByteString promotedUserId = ByteString.copyFromUtf8("promoted");
    final ByteString remainingUserId = ByteString.copyFromUtf8("remaining");
    final ByteString newProfileKey = ByteString.copyFromUtf8("new profile key");

    final MemberPendingProfileKey remaining = pendingMember(remainingUserId);
    final Group group = Group.newBuilder()
        .setVersion(4)
        .addMembersPendingProfileKey(pendingMember(promotedUserId))
        .addMembersPendingProfileKey(remaining)
        .build();

    final Group.Builder modifiedGroupBuilder = group.toBuilder();
    // switches the field to RepeatedFieldBuilder storage, after which getMembersPendingProfileKeyList() is a live view
    modifiedGroupBuilder.getMembersPendingProfileKeyBuilderList();

    groupChangeApplicator.applyPromoteMembersPendingProfileKey(null, null, group, modifiedGroupBuilder,
        List.of(PromoteMemberPendingProfileKeyAction.newBuilder()
            .setUserId(promotedUserId)
            .setProfileKey(newProfileKey)
            .build()));

    assertThat(modifiedGroupBuilder.getMembersPendingProfileKeyList()).containsExactly(remaining);
    assertThat(modifiedGroupBuilder.getMembersList()).containsExactly(Member.newBuilder()
        .setUserId(promotedUserId)
        .setRole(Member.Role.DEFAULT)
        .setProfileKey(newProfileKey)
        .setJoinedAtVersion(5)
        .build());
  }

  private static MemberPendingProfileKey pendingMember(final ByteString userId) {
    return MemberPendingProfileKey.newBuilder()
        .setMember(Member.newBuilder().setUserId(userId).setRole(Member.Role.DEFAULT))
        .setAddedByUserId(ByteString.copyFromUtf8("admin"))
        .setTimestamp(1234)
        .build();
  }
}
