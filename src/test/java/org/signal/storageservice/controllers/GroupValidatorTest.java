/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.controllers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.google.protobuf.ByteString;
import jakarta.ws.rs.BadRequestException;
import org.junit.jupiter.api.Test;
import org.signal.libsignal.zkgroup.profiles.ServerZkProfileOperations;
import org.signal.storageservice.auth.GroupUser;
import org.signal.storageservice.groups.GroupValidator;
import org.signal.storageservice.storage.protos.groups.Group;
import org.signal.storageservice.storage.protos.groups.GroupChange;
import org.signal.storageservice.storage.protos.groups.GroupChange.Actions.AddMemberPendingAdminApprovalAction;
import org.signal.storageservice.storage.protos.groups.GroupChange.Actions.DeleteMemberPendingProfileKeyAction;
import org.signal.storageservice.storage.protos.groups.GroupChange.Actions.ModifyDescriptionAction;
import org.signal.storageservice.storage.protos.groups.GroupChange.Actions.PromoteMemberPendingPniAciProfileKeyAction;
import org.signal.storageservice.storage.protos.groups.Member;
import org.signal.storageservice.storage.protos.groups.MemberPendingAdminApproval;
import org.signal.storageservice.storage.protos.groups.MemberPendingProfileKey;
import org.signal.storageservice.util.AuthHelper;
import java.util.Optional;

public class GroupValidatorTest extends BaseGroupsControllerTest {

  final GroupValidator validator = new GroupValidator(
      new ServerZkProfileOperations(AuthHelper.GROUPS_SERVER_KEY),
      getGroupConfiguration());

  GroupUser testUserThree() {
    return new GroupUser(
        validUserThreeId,
        validUserThreePniId,
        ByteString.copyFrom(groupPublicParams.serialize()),
        ByteString.copyFrom(groupPublicParams.getGroupIdentifier().serialize()));
  }

  Group groupWithPendingInvite(ByteString userId) {
    return groupWithPendingInvite(group, userId);
  }

  Group groupWithPendingInvite(Group initialState, ByteString userId) {
    return initialState
        .toBuilder()
        .addMembersPendingProfileKey(MemberPendingProfileKey
            .newBuilder()
            .setMember(Member
                .newBuilder()
                .setUserId(userId)
                .setRole(Member.Role.DEFAULT))
            .setAddedByUserId(validUserId)
            .setTimestamp(clock.millis()))
        .build();
  }

  @Test
  void choosesPniAsChangeSourceForAcceptingPniInvite() {
    Optional<ByteString> source = validator.validateSpecialChangeSourceActions(
        testUserThree(),
        groupWithPendingInvite(validUserThreePniId),
        GroupChange.Actions
            .newBuilder()
            .setVersion(1)
            .addPromoteMembersPendingPniAciProfileKey(PromoteMemberPendingPniAciProfileKeyAction
                .newBuilder()
                .setPni(validUserThreePniId)
                .setUserId(validUserThreeId)
                .setPresentation(ByteString.copyFrom(validUserThreePresentation.serialize())))
            .build()
        );
    assertThat(source.get()).isEqualTo(validUserThreePniId);
  }

  @Test
  void choosesPniAsChangeSourceForDecliningPniInvite() {
    Optional<ByteString> source = validator.validateSpecialChangeSourceActions(
        testUserThree(),
        groupWithPendingInvite(validUserThreePniId),
        GroupChange.Actions
            .newBuilder()
            .setVersion(1)
            .addDeleteMembersPendingProfileKey(DeleteMemberPendingProfileKeyAction
                .newBuilder()
                .setDeletedUserId(validUserThreePniId))
            .build()
    );
    assertThat(source.get()).isEqualTo(validUserThreePniId);
  }

  @Test
  void doesNotOverrideChangeSourceForAdminPromotingOtherUsers() {
    Optional<ByteString> source = validator.validateSpecialChangeSourceActions(
        new GroupUser(
            validUserId,
            validUserPniId,
            ByteString.copyFrom(groupPublicParams.serialize()),
            ByteString.copyFrom(groupPublicParams.getGroupIdentifier().serialize())),
        groupWithPendingInvite(groupWithPendingInvite(validUserPniId), validUserFourPniId),
        GroupChange.Actions
            .newBuilder()
            .setVersion(1)
            .addPromoteMembersPendingPniAciProfileKey(PromoteMemberPendingPniAciProfileKeyAction
                .newBuilder()
                .setPni(validUserFourPniId)
                .setUserId(validUserFourId)
                .setPresentation(ByteString.copyFrom(validUserFourPresentation.serialize())))
            .build()
    );
    assertThat(source).isEqualTo(Optional.empty());
  }

  @Test
  void doesNotOverrideChangeSourceForAdminDecliningPniInvite() {
    Optional<ByteString> source = validator.validateSpecialChangeSourceActions(
        new GroupUser(
            validUserId,
            validUserPniId,
            ByteString.copyFrom(groupPublicParams.serialize()),
            ByteString.copyFrom(groupPublicParams.getGroupIdentifier().serialize())),
        groupWithPendingInvite(groupWithPendingInvite(validUserPniId), validUserFourPniId),
        GroupChange.Actions
            .newBuilder()
            .setVersion(1)
            .addDeleteMembersPendingProfileKey(DeleteMemberPendingProfileKeyAction
                .newBuilder()
                .setDeletedUserId(validUserPniId))
            // They can even delete more than one user at a time
            .addDeleteMembersPendingProfileKey(DeleteMemberPendingProfileKeyAction
                .newBuilder()
                .setDeletedUserId(validUserFourPniId))
            .build()
    );
    assertThat(source).isEqualTo(Optional.empty());
  }

  @Test
  void doesNotOverrideChangeSourceForSomeOtherChange() {
    Optional<ByteString> source = validator.validateSpecialChangeSourceActions(
        testUserThree(),
        groupWithPendingInvite(validUserThreePniId),
        GroupChange.Actions
            .newBuilder()
            .setVersion(1)
            .addAddMembersPendingAdminApproval(AddMemberPendingAdminApprovalAction
                .newBuilder()
                .setAdded(MemberPendingAdminApproval
                    .newBuilder()
                    .setUserId(validUserThreeId)
                    .setPresentation(ByteString.copyFrom(validUserThreePresentation.serialize()))
                    .setTimestamp(clock.millis())))
            .build()
    );
    assertThat(source).isEqualTo(Optional.empty());
  }

  @Test
  void disallowsPromotePniForTwoUsers() {
    assertThatThrownBy(() -> validator.validateSpecialChangeSourceActions(
        testUserThree(),
        groupWithPendingInvite(groupWithPendingInvite(validUserThreePniId), validUserFourPniId),
        GroupChange.Actions
            .newBuilder()
            .setVersion(1)
            .addPromoteMembersPendingPniAciProfileKey(PromoteMemberPendingPniAciProfileKeyAction
                .newBuilder()
                .setPni(validUserThreePniId)
                .setUserId(validUserThreeId)
                .setPresentation(ByteString.copyFrom(validUserThreePresentation.serialize())))
            .addPromoteMembersPendingPniAciProfileKey(PromoteMemberPendingPniAciProfileKeyAction
                .newBuilder()
                .setPni(validUserFourPniId)
                .setUserId(validUserFourId)
                .setPresentation(ByteString.copyFrom(validUserFourPresentation.serialize())))
            .build()
    )).isInstanceOf(BadRequestException.class);
  }

  @Test
  void disallowsPromotePniWithAnotherAction() {
    assertThatThrownBy(() -> validator.validateSpecialChangeSourceActions(
        testUserThree(),
        groupWithPendingInvite(validUserThreePniId),
        GroupChange.Actions
            .newBuilder()
            .setVersion(1)
            .addPromoteMembersPendingPniAciProfileKey(PromoteMemberPendingPniAciProfileKeyAction
                .newBuilder()
                .setPni(validUserThreePniId)
                .setUserId(validUserThreeId)
                .setPresentation(ByteString.copyFrom(validUserThreePresentation.serialize())))
            .setModifyDescription(ModifyDescriptionAction
                .newBuilder()
                .setDescription(ByteString.empty()))
            .build()
    )).isInstanceOf(BadRequestException.class);
  }

  @Test
  void disallowsDeclinePniInviteForTwoUsers() {
    assertThatThrownBy(() -> validator.validateSpecialChangeSourceActions(
        testUserThree(),
        groupWithPendingInvite(groupWithPendingInvite(validUserThreePniId), validUserFourPniId),
        GroupChange.Actions
            .newBuilder()
            .setVersion(1)
            .addDeleteMembersPendingProfileKey(DeleteMemberPendingProfileKeyAction
                .newBuilder()
                .setDeletedUserId(validUserThreePniId))
            .addDeleteMembersPendingProfileKey(DeleteMemberPendingProfileKeyAction
                .newBuilder()
                .setDeletedUserId(validUserFourPniId))
            .build()
    )).isInstanceOf(BadRequestException.class);
  }

  @Test
  void disallowsDeclinePniInviteWithAnotherAction() {
    assertThatThrownBy(() -> validator.validateSpecialChangeSourceActions(
        testUserThree(),
        groupWithPendingInvite(validUserThreePniId),
        GroupChange.Actions
            .newBuilder()
            .setVersion(1)
            .addDeleteMembersPendingProfileKey(DeleteMemberPendingProfileKeyAction
                .newBuilder()
                .setDeletedUserId(validUserThreePniId))
            .setModifyDescription(ModifyDescriptionAction
                .newBuilder()
                .setDescription(ByteString.empty()))
            .build()
    )).isInstanceOf(BadRequestException.class);
  }
}
