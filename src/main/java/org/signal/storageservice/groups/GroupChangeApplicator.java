/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.groups;

import com.google.protobuf.ByteString;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.ForbiddenException;
import org.signal.storageservice.auth.GroupUser;
import org.signal.storageservice.storage.protos.groups.AccessControl;
import org.signal.storageservice.storage.protos.groups.Group;
import org.signal.storageservice.storage.protos.groups.GroupChange;
import org.signal.storageservice.storage.protos.groups.GroupChange.Actions;
import org.signal.storageservice.storage.protos.groups.GroupChange.Actions.AddMemberBannedAction;
import org.signal.storageservice.storage.protos.groups.GroupChange.Actions.DeleteMemberBannedAction;
import org.signal.storageservice.storage.protos.groups.Member;
import org.signal.storageservice.storage.protos.groups.Member.Role;
import org.signal.storageservice.storage.protos.groups.MemberBanned;
import org.signal.storageservice.storage.protos.groups.MemberPendingAdminApproval;
import org.signal.storageservice.storage.protos.groups.MemberPendingProfileKey;
import org.signal.storageservice.util.CollectionUtil;

public class GroupChangeApplicator {
  private final GroupValidator groupValidator;

  public GroupChangeApplicator(GroupValidator groupValidator) {
    this.groupValidator = groupValidator;
  }

  public void applyAddMembers(GroupUser user,
                              byte[] inviteLinkPassword,
                              Group group,
                              Group.Builder modifiedGroupBuilder,
                              List<GroupChange.Actions.AddMemberAction> addMembers)
          throws ForbiddenException, BadRequestException {
    if (addMembers.isEmpty()) {
      return;
    }

    if (!GroupAuth.isAddMembersAllowed(user, inviteLinkPassword, group, addMembers)) {
      throw new ForbiddenException();
    }

    if (addMembers.stream().anyMatch(member -> member.getAdded().getRole() == Member.Role.ADMINISTRATOR) && !GroupAuth.isAdminstrator(user, group)) {
      throw new ForbiddenException();
    }

    if (CollectionUtil.containsDuplicates(addMembers.stream().map(action -> action.getAdded().getUserId()).collect(Collectors.toList()))) {
      throw new BadRequestException();
    }

    if (CollectionUtil.containsAny(group.getMembersList().stream().map(Member::getUserId).collect(Collectors.toList()),
                                   addMembers.stream().map(action -> action.getAdded().getUserId()).collect(Collectors.toList()))) {
      throw new BadRequestException();
    }

    for (GroupChange.Actions.AddMemberAction action : addMembers) {
      final ByteString userId = action.getAdded().getUserId();
      if (userId == null || userId.isEmpty()) {
        throw new BadRequestException();
      }

      if (action.getAdded().getProfileKey() == null || action.getAdded().getProfileKey().isEmpty()) {
        throw new BadRequestException();
      }

      if (action.getAdded().getRole() == Member.Role.UNKNOWN || action.getAdded().getRole() == Member.Role.UNRECOGNIZED) {
        throw new BadRequestException();
      }

      modifiedGroupBuilder.addMembers(Member.newBuilder()
                                            .setRole(action.getAdded().getRole())
                                            .setJoinedAtVersion(group.getVersion() + 1)
                                            .setUserId(userId)
                                            .setProfileKey(action.getAdded().getProfileKey()));

      for (int i = 0; i < modifiedGroupBuilder.getMembersPendingProfileKeyList().size(); i++) {
        if (userId.equals(modifiedGroupBuilder.getMembersPendingProfileKey(i).getMember().getUserId())) {
          modifiedGroupBuilder.removeMembersPendingProfileKey(i);
          i--;  // decrement i because subsequent elements have shifted to the left
        }
      }
      for (int i = 0; i < modifiedGroupBuilder.getMembersPendingAdminApprovalList().size(); i++) {
        if (userId.equals(modifiedGroupBuilder.getMembersPendingAdminApproval(i).getUserId())) {
          modifiedGroupBuilder.removeMembersPendingAdminApproval(i);
          i--;  // decrement i because subsequent elements have shifted to the left
        }
      }
    }
  }

  public void applyDeleteMembers(GroupUser user, byte[] inviteLinkPassword, Group group, Group.Builder modifiedGroupBuilder, List<GroupChange.Actions.DeleteMemberAction> deleteMembers)
          throws BadRequestException, ForbiddenException {
    if (deleteMembers.isEmpty()) {
      return;
    }

    if (CollectionUtil.containsDuplicates(deleteMembers.stream().map(GroupChange.Actions.DeleteMemberAction::getDeletedUserId).collect(Collectors.toList()))) {
      throw new BadRequestException();
    }

    if (!GroupAuth.isDeleteMembersAllowed(user, group, deleteMembers)) {
      throw new ForbiddenException();
    }

    Set<ByteString> currentMemberUuids = modifiedGroupBuilder.getMembersList().stream().map(Member::getUserId).collect(Collectors.toSet());
    Set<ByteString> deleteMemberUuids  = deleteMembers.stream().map(GroupChange.Actions.DeleteMemberAction::getDeletedUserId).collect(Collectors.toSet());

    if (!currentMemberUuids.containsAll(deleteMemberUuids)) {
      throw new BadRequestException();
    }

    // XXX Remove last admin or last member?

    List<Member> membership = modifiedGroupBuilder.getMembersList().stream().filter(member -> !deleteMemberUuids.contains(member.getUserId())).collect(Collectors.toList());

    modifiedGroupBuilder.clearMembers().addAllMembers(membership);
  }

  public void applyModifyMemberRoles(GroupUser user, byte[] inviteLinkPassword, Group group, Group.Builder modifiedGroupBuilder, List<GroupChange.Actions.ModifyMemberRoleAction> modifyMembers)
          throws BadRequestException, ForbiddenException {
    if (modifyMembers.isEmpty()) {
      return;
    }

    if (modifyMembers.stream().anyMatch(modify -> modify.getUserId() == null || modify.getUserId().isEmpty())) {
      throw new BadRequestException();
    }

    if (modifyMembers.stream().anyMatch(modify -> modify.getRole() == Member.Role.UNKNOWN || modify.getRole() == Member.Role.UNRECOGNIZED)) {
      throw new BadRequestException();
    }

    if (CollectionUtil.containsDuplicates(modifyMembers.stream().map(GroupChange.Actions.ModifyMemberRoleAction::getUserId).collect(Collectors.toList()))) {
      throw new BadRequestException();
    }

    if (!GroupAuth.isAdminstrator(user, group)) {
      throw new ForbiddenException();
    }

    if (!modifiedGroupBuilder.getMembersList().stream().map(Member::getUserId).collect(Collectors.toSet())
                             .containsAll(modifyMembers.stream().map(GroupChange.Actions.ModifyMemberRoleAction::getUserId).collect(Collectors.toList()))) {
      throw new BadRequestException();
    }

    List<Member> currentMembership = modifiedGroupBuilder.getMembersList();
    List<Member> newMembership     = new LinkedList<>();

    for (Member member : currentMembership) {
      Optional<GroupChange.Actions.ModifyMemberRoleAction> action = modifyMembers.stream().filter(candidate -> candidate.getUserId().equals(member.getUserId())).findAny();

      if (action.isPresent()) {
        newMembership.add(member.toBuilder().setRole(action.get().getRole()).build());
      } else {
        newMembership.add(member);
      }
    }

    modifiedGroupBuilder.clearMembers().addAllMembers(newMembership);
  }

  public void applyModifyMemberProfileKeys(GroupUser user, byte[] inviteLinkPassword, Group group, Group.Builder modifiedGroupBuilder, List<GroupChange.Actions.ModifyMemberProfileKeyAction> modifyMembers)
          throws BadRequestException, ForbiddenException {
    if (modifyMembers.isEmpty()) {
      return;
    }

    for (GroupChange.Actions.ModifyMemberProfileKeyAction action : modifyMembers) {
      List<Member> currentMembers = modifiedGroupBuilder.getMembersList();
      Member member = currentMembers.stream()
                                    .filter(candidate -> candidate.getUserId().equals(action.getUserId()))
                                    .findFirst()
                                    .orElseThrow(ForbiddenException::new)
                                    .toBuilder()
                                    .clearPresentation()
                                    .clearProfileKey()
                                    .setProfileKey(action.getProfileKey())
                                    .build();

      modifiedGroupBuilder.clearMembers()
                          .addAllMembers(currentMembers.stream().map(candidate -> {
                            if (candidate.getUserId().equals(member.getUserId())) return member;
                            else return candidate;
                          }).collect(Collectors.toList()));
    }
  }

  public void applyAddMembersPendingProfileKey(GroupUser user,
                                               byte[] inviteLinkPassword,
                                               Group group,
                                               Group.Builder modifiedGroupBuilder,
                                               List<GroupChange.Actions.AddMemberPendingProfileKeyAction> addMembersPendingProfileKey)
          throws ForbiddenException, BadRequestException {
    if (addMembersPendingProfileKey.isEmpty()) {
      return;
    }

    if (!GroupAuth.isAddMembersPendingProfileKeyAllowed(user, group)) {
      throw new ForbiddenException();
    }

    if (addMembersPendingProfileKey.stream().anyMatch(pending -> pending.getAdded().getMember().getRole() == Member.Role.ADMINISTRATOR) &&
            !GroupAuth.isAdminstrator(user, group)) {
      throw new ForbiddenException();
    }

    if (CollectionUtil.containsDuplicates(addMembersPendingProfileKey.stream().map(pending -> pending.getAdded().getMember().getUserId()).collect(Collectors.toList()))) {
      throw new BadRequestException();
    }

    Stream<ByteString> existingMembers                  = group.getMembersList().stream().map(Member::getUserId);
    Stream<ByteString> existingMembersPendingProfileKey = group.getMembersPendingProfileKeyList().stream().map(pending -> pending.getMember().getUserId());

    if (CollectionUtil.containsAny(Stream.concat(existingMembers, existingMembersPendingProfileKey).collect(Collectors.toList()),
                                   addMembersPendingProfileKey.stream().map(action -> action.getAdded().getMember().getUserId()).collect(Collectors.toList()))) {
      throw new BadRequestException("Member is already present");
    }

    for (GroupChange.Actions.AddMemberPendingProfileKeyAction action : addMembersPendingProfileKey) {
      if (!action.getAdded().hasMember() || action.getAdded().getMember() == null) {
        throw new BadRequestException("No member");
      }

      if (action.getAdded().getMember().getUserId() == null || action.getAdded().getMember().getUserId().isEmpty()) {
        throw new BadRequestException("No user id");
      }

      if (action.getAdded().getMember().getProfileKey() != null && !action.getAdded().getMember().getProfileKey().isEmpty()) {
        throw new BadRequestException("Profile key present for invitation");
      }

      if (action.getAdded().getMember().getPresentation() != null && !action.getAdded().getMember().getPresentation().isEmpty()) {
        throw new BadRequestException("Presentation not empty for invitation");
      }

      if (action.getAdded().getMember().getRole() == Member.Role.UNKNOWN || action.getAdded().getMember().getRole() == Member.Role.UNRECOGNIZED) {
        throw new BadRequestException();
      }

      modifiedGroupBuilder.addMembersPendingProfileKey(
              MemberPendingProfileKey.newBuilder()
                                     .setMember(Member.newBuilder()
                                                      .setRole(action.getAdded().getMember().getRole())
                                                      .setUserId(action.getAdded().getMember().getUserId())
                                                      .setJoinedAtVersion(group.getVersion() + 1)
                                                      .build())
                                     .setAddedByUserId(GroupAuth.getMember(user, group).get().getUserId())
                                     .setTimestamp(System.currentTimeMillis())
                                     .build());
    }
  }

  public void applyDeleteMembersPendingProfileKey(GroupUser user, byte[] inviteLinkPassword, Group group, Group.Builder modifiedGroupBuilder, List<GroupChange.Actions.DeleteMemberPendingProfileKeyAction> deleteMembersPendingProfileKey)
          throws BadRequestException, ForbiddenException {
    if (deleteMembersPendingProfileKey.isEmpty()) {
      return;
    }

    if (CollectionUtil.containsDuplicates(deleteMembersPendingProfileKey.stream().map(GroupChange.Actions.DeleteMemberPendingProfileKeyAction::getDeletedUserId).collect(Collectors.toList()))) {
      throw new BadRequestException();
    }

    if (!GroupAuth.isDeleteMembersPendingProfileKeyAllowed(user, group, deleteMembersPendingProfileKey)) {
      throw new ForbiddenException();
    }

    Set<ByteString> currentMembersPendingProfileKeyUuids = modifiedGroupBuilder.getMembersPendingProfileKeyList().stream().map(pending -> pending.getMember().getUserId()).collect(Collectors.toSet());
    Set<ByteString> deleteMembersPendingProfileKeyUuids  = deleteMembersPendingProfileKey.stream().map(GroupChange.Actions.DeleteMemberPendingProfileKeyAction::getDeletedUserId).collect(Collectors.toSet());

    if (!currentMembersPendingProfileKeyUuids.containsAll(deleteMembersPendingProfileKeyUuids)) {
      throw new BadRequestException();
    }

    List<MemberPendingProfileKey> membership = modifiedGroupBuilder.getMembersPendingProfileKeyList()
                                                                   .stream()
                                                                   .filter(memberPendingProfileKey -> !deleteMembersPendingProfileKeyUuids.contains(memberPendingProfileKey.getMember().getUserId()))
                                                                   .collect(Collectors.toList());

    modifiedGroupBuilder.clearMembersPendingProfileKey().addAllMembersPendingProfileKey(membership);
  }

  public void applyPromoteMembersPendingProfileKey(GroupUser user, byte[] inviteLinkPassword, Group group, Group.Builder modifiedGroupBuilder, List<GroupChange.Actions.PromoteMemberPendingProfileKeyAction> promoteMembersPendingProfileKey)
          throws BadRequestException, ForbiddenException {
    if (promoteMembersPendingProfileKey.isEmpty()) {
      return;
    }

    for (GroupChange.Actions.PromoteMemberPendingProfileKeyAction action : promoteMembersPendingProfileKey) {
      List<MemberPendingProfileKey> membersPendingProfileKey = modifiedGroupBuilder.getMembersPendingProfileKeyList();
      MemberPendingProfileKey memberPendingProfileKey = membersPendingProfileKey.stream()
                                                                                .filter(candidate -> candidate.getMember().getUserId().equals(action.getUserId()))
                                                                                .findFirst()
                                                                                .orElseThrow(ForbiddenException::new);

      modifiedGroupBuilder.clearMembersPendingProfileKey()
                          .addAllMembersPendingProfileKey(membersPendingProfileKey.stream()
                                                                                  .filter(candidate -> !candidate.getMember().getUserId().equals(action.getUserId()))
                                                                                  .collect(Collectors.toList()));

      modifiedGroupBuilder.addMembers(memberPendingProfileKey.getMember()
                                                             .toBuilder()
                                                             .clearPresentation()
                                                             .clearProfileKey()
                                                             .setProfileKey(action.getProfileKey())
                                                             .setJoinedAtVersion(group.getVersion() + 1));
    }
  }

  public void applyPromoteMembersPendingPniAciProfileKey(GroupUser user, byte[] inviteLinkPassword, Group group, Group.Builder modifiedGroupBuilder, List<GroupChange.Actions.PromoteMemberPendingPniAciProfileKeyAction> promoteMembersPendingPniAciProfileKey)
      throws BadRequestException, ForbiddenException {

    if (promoteMembersPendingPniAciProfileKey.isEmpty()) {
      return;
    }

    for (GroupChange.Actions.PromoteMemberPendingPniAciProfileKeyAction action : promoteMembersPendingPniAciProfileKey) {
      final List<MemberPendingProfileKey> membersPendingProfileKey = modifiedGroupBuilder.getMembersPendingProfileKeyList();

      final MemberPendingProfileKey memberPendingProfileKey = membersPendingProfileKey.stream()
          .filter(candidate -> candidate.getMember().getUserId().equals(action.getPni()))
          .findFirst()
          .orElseThrow(ForbiddenException::new);

      modifiedGroupBuilder.clearMembersPendingProfileKey()
          .addAllMembersPendingProfileKey(membersPendingProfileKey.stream()
              .filter(candidate -> !(candidate.getMember().getUserId().equals(action.getUserId()) || candidate.getMember().getUserId().equals(action.getPni())))
              .collect(Collectors.toList()));

      modifiedGroupBuilder.addMembers(memberPendingProfileKey.getMember()
          .toBuilder()
          .clearPresentation()
          .clearProfileKey()
          .clearUserId()
          .setUserId(action.getUserId())
          .setProfileKey(action.getProfileKey())
          .setJoinedAtVersion(group.getVersion() + 1));
    }
  }

  public void applyModifyTitle(GroupUser user, byte[] inviteLinkPassword, Group group, Group.Builder modifiedGroupBuilder, GroupChange.Actions.ModifyTitleAction modifyTitle)
          throws ForbiddenException, BadRequestException {
    if (modifyTitle == null) {
      return;
    }

    if (modifyTitle.getTitle() == null || modifyTitle.getTitle().isEmpty()) {
      throw new BadRequestException();
    }

    if (!GroupAuth.isModifyAttributesAllowed(user, group)) {
      throw new ForbiddenException();
    }

    modifiedGroupBuilder.setTitle(modifyTitle.getTitle());
  }

  public void applyModifyDescription(GroupUser user, byte[] inviteLinkPassword, Group group, Group.Builder modifiedGroupBuilder, GroupChange.Actions.ModifyDescriptionAction modifyDescription) {
    if (modifyDescription == null) {
      return;
    }

    if (!GroupAuth.isModifyAttributesAllowed(user, group)) {
      throw new ForbiddenException("modify description forbidden");
    }

    modifiedGroupBuilder.setDescription(modifyDescription.getDescription());
  }

  public void applyModifyAvatar(GroupUser user, byte[] inviteLinkPassword, Group group, Group.Builder modifiedGroupBuilder, GroupChange.Actions.ModifyAvatarAction modifyAvatar)
          throws ForbiddenException, BadRequestException {
    if (modifyAvatar == null) {
      return;
    }

    if (!GroupAuth.isModifyAttributesAllowed(user, group)) {
      throw new ForbiddenException();
    }

    if (!groupValidator.isValidAvatarUrl(modifyAvatar.getAvatar(), user.getGroupId())) {
      throw new BadRequestException();
    }

    modifiedGroupBuilder.setAvatar(modifyAvatar.getAvatar());
  }

  public void applyModifyDisappearingMessageTimer(GroupUser user, byte[] inviteLinkPassword, Group group, Group.Builder modifiedGroupBuilder, GroupChange.Actions.ModifyDisappearingMessageTimerAction modifyDisappearingMessageTimer)
          throws ForbiddenException {
    if (modifyDisappearingMessageTimer == null) {
      return;
    }

    if (!GroupAuth.isModifyAttributesAllowed(user, group)) {
      throw new ForbiddenException();
    }

    modifiedGroupBuilder.setDisappearingMessagesTimer(modifyDisappearingMessageTimer.getTimer());
  }

  public void applyModifyAttributesAccess(GroupUser user, byte[] inviteLinkPassword, Group group, Group.Builder modifiedGroupBuilder, GroupChange.Actions.ModifyAttributesAccessControlAction modifyAttributesAccess) throws ForbiddenException, BadRequestException {
    if (modifyAttributesAccess == null || !modifyAttributesAccess.isInitialized()) {
      throw new BadRequestException();
    }

    if (modifyAttributesAccess.getAttributesAccess() != AccessControl.AccessRequired.ADMINISTRATOR &&
        modifyAttributesAccess.getAttributesAccess() != AccessControl.AccessRequired.MEMBER) {
      throw new BadRequestException();
    }

    if (!GroupAuth.isAdminstrator(user, group)) {
      throw new ForbiddenException();
    }

    modifiedGroupBuilder.setAccessControl(modifiedGroupBuilder.getAccessControlBuilder().setAttributes(modifyAttributesAccess.getAttributesAccess()));
  }

  public void applyModifyMembersAccess(GroupUser user, byte[] inviteLinkPassword, Group group, Group.Builder modifiedGroupBuilder, GroupChange.Actions.ModifyMembersAccessControlAction modifyMembersAccess) throws ForbiddenException, BadRequestException {
    if (modifyMembersAccess == null || !modifyMembersAccess.isInitialized()) {
      throw new BadRequestException();
    }

    if (modifyMembersAccess.getMembersAccess() != AccessControl.AccessRequired.ADMINISTRATOR &&
        modifyMembersAccess.getMembersAccess() != AccessControl.AccessRequired.MEMBER) {
      throw new BadRequestException();
    }

    if (!GroupAuth.isAdminstrator(user, group)) {
      throw new ForbiddenException();
    }

    modifiedGroupBuilder.setAccessControl(modifiedGroupBuilder.getAccessControlBuilder().setMembers(modifyMembersAccess.getMembersAccess()));
  }

  public void applyModifyAddFromInviteLinkAccess(GroupUser user, byte[] inviteLinkPassword, Group group, Group.Builder modifiedGroupBuilder, GroupChange.Actions.ModifyAddFromInviteLinkAccessControlAction action) throws ForbiddenException, BadRequestException {
    if (!GroupAuth.isModifyAddFromInviteLinkAccessControlAllowed(user, group)) {
      throw new ForbiddenException();
    }

    if (action.getAddFromInviteLinkAccess() != AccessControl.AccessRequired.ANY &&
        action.getAddFromInviteLinkAccess() != AccessControl.AccessRequired.ADMINISTRATOR &&
        action.getAddFromInviteLinkAccess() != AccessControl.AccessRequired.UNSATISFIABLE) {
      throw new BadRequestException();
    }

    modifiedGroupBuilder.setAccessControl(modifiedGroupBuilder.getAccessControlBuilder().setAddFromInviteLink(action.getAddFromInviteLinkAccess()));
  }

  public void applyAddMembersPendingAdminApproval(GroupUser user, byte[] inviteLinkPassword, Group group, Group.Builder modifiedGroupBuilder, List<GroupChange.Actions.AddMemberPendingAdminApprovalAction> actions) throws ForbiddenException {
    if (!GroupAuth.isAddMembersPendingAdminApprovalAllowed(user, inviteLinkPassword, group)) {
      throw new ForbiddenException();
    }

    final List<ByteString> addedUserIds = actions.stream().map(addMemberPendingAdminApprovalAction -> addMemberPendingAdminApprovalAction.getAdded().getUserId()).collect(Collectors.toList());

    if (CollectionUtil.containsAny(modifiedGroupBuilder.getMembersList().stream().map(Member::getUserId).collect(Collectors.toSet()), addedUserIds)) {
      throw new BadRequestException("cannot ask to join via invite link if already in group");
    }

    if (CollectionUtil.containsAny(modifiedGroupBuilder.getMembersPendingProfileKeyList().stream().map(memberPendingProfileKey -> memberPendingProfileKey.getMember().getUserId()).collect(Collectors.toSet()), addedUserIds)) {
      throw new BadRequestException("cannot ask to join via invite link if already in group pending profile key");
    }

    if (CollectionUtil.containsAny(modifiedGroupBuilder.getMembersPendingAdminApprovalList().stream().map(MemberPendingAdminApproval::getUserId).collect(Collectors.toSet()), addedUserIds)) {
      throw new BadRequestException("cannot ask to join via invite link if already asked to join");
    }

    if (CollectionUtil.containsDuplicates(addedUserIds)) {
      throw new BadRequestException("duplicate user ids in request");
    }

    if (addedUserIds.size() != 1 || !user.isMember(addedUserIds.get(0), group.getPublicKey())) {
      throw new BadRequestException("request contains non-self user ids");
    }

    actions.stream().map(GroupChange.Actions.AddMemberPendingAdminApprovalAction::getAdded).forEach(modifiedGroupBuilder::addMembersPendingAdminApproval);
  }

  public void applyDeleteMembersPendingAdminApproval(GroupUser user, byte[] inviteLinkPassword, Group group, Group.Builder modifiedGroupBuilder, List<GroupChange.Actions.DeleteMemberPendingAdminApprovalAction> actions) throws ForbiddenException {
    if (!GroupAuth.isDeleteMembersPendingAdminApprovalAllowed(user, group, actions)) {
      throw new ForbiddenException();
    }

    Set<ByteString> userIdsToRemove = actions.stream().map(GroupChange.Actions.DeleteMemberPendingAdminApprovalAction::getDeletedUserId).collect(Collectors.toSet());

    if (userIdsToRemove.size() != actions.size()) {
      throw new BadRequestException("duplicate user ids in request");
    }

    Set<ByteString> currentUserIds = modifiedGroupBuilder.getMembersPendingAdminApprovalList().stream().map(MemberPendingAdminApproval::getUserId).collect(Collectors.toSet());

    if (!currentUserIds.containsAll(userIdsToRemove)) {
      throw new BadRequestException("some user ids not pending admin approval");
    }

    List<MemberPendingAdminApproval> members = modifiedGroupBuilder.getMembersPendingAdminApprovalList()
                                                                   .stream()
                                                                   .filter(member -> !userIdsToRemove.contains(member.getUserId()))
                                                                   .collect(Collectors.toList());

    modifiedGroupBuilder.clearMembersPendingAdminApproval().addAllMembersPendingAdminApproval(members);
  }

  public void applyPromotePendingAdminApproval(GroupUser user, byte[] inviteLinkPassword, Group group, Group.Builder modifiedGroupBuilder, List<GroupChange.Actions.PromoteMemberPendingAdminApprovalAction> actions) throws ForbiddenException {
    if (!GroupAuth.isPromoteMembersPendingAdminApprovalAllowed(user, group)) {
      throw new ForbiddenException();
    }

    Map<ByteString, Member.Role> userIdToRoleMap = actions.stream().collect(Collectors.toMap(GroupChange.Actions.PromoteMemberPendingAdminApprovalAction::getUserId,
                                                                                             GroupChange.Actions.PromoteMemberPendingAdminApprovalAction::getRole,
                                                                                             (role1, role2) -> role1));

    if (userIdToRoleMap.size() != actions.size()) {
      throw new BadRequestException("duplicate user ids in request");
    }

    if (CollectionUtil.containsAny(userIdToRoleMap.keySet(), modifiedGroupBuilder.getMembersList().stream().map(Member::getUserId).collect(Collectors.toList()))) {
      throw new BadRequestException("some user ids already in members");
    }

    for (Map.Entry<ByteString, Member.Role> entry : userIdToRoleMap.entrySet()) {
      Optional<MemberPendingAdminApproval> memberPendingAdminApproval = modifiedGroupBuilder.getMembersPendingAdminApprovalList().stream().filter(m -> m.getUserId().equals(entry.getKey())).findFirst();
      if (memberPendingAdminApproval.isEmpty()) {
        throw new BadRequestException("some user ids were not in the set of members pending admin approval");
      }

      modifiedGroupBuilder.addMembers(Member.newBuilder()
                                            .setUserId(entry.getKey())
                                            .setRole(entry.getValue())
                                            .setJoinedAtVersion(group.getVersion() + 1)
                                            .setProfileKey(memberPendingAdminApproval.get().getProfileKey()));
    }

    List<MemberPendingAdminApproval> members = modifiedGroupBuilder.getMembersPendingAdminApprovalList()
                                                                   .stream()
                                                                   .filter(member -> !userIdToRoleMap.containsKey(member.getUserId()))
                                                                   .collect(Collectors.toList());
    modifiedGroupBuilder.clearMembersPendingAdminApproval()
                        .addAllMembersPendingAdminApproval(members);
  }

  public void applyModifyInviteLinkPassword(GroupUser user, byte[] inviteLinkPassword, Group group, Group.Builder modifiedGroupBuilder, GroupChange.Actions.ModifyInviteLinkPasswordAction modifyInviteLinkPassword) throws ForbiddenException {
    if (!GroupAuth.isModifyInviteLinkPasswordAllowed(user, group)) {
      throw new ForbiddenException();
    }

    modifiedGroupBuilder.setInviteLinkPassword(modifyInviteLinkPassword.getInviteLinkPassword());
  }

  public void applyModifyAnnouncementsOnly(GroupUser user, byte[] inviteLinkPassword, Group group, Group.Builder modifiedGroupBuilder, GroupChange.Actions.ModifyAnnouncementsOnlyAction modifyAnnouncementsOnly) throws ForbiddenException {
    if (!GroupAuth.isModifyAnnouncementsOnlyAllowed(user, group)) {
      throw new ForbiddenException();
    }

    modifiedGroupBuilder.setAnnouncementsOnly(modifyAnnouncementsOnly.getAnnouncementsOnly());
  }

  public void applyEnsureSomeAdminsExist(Actions.Builder actionsBuilder, Group.Builder modifiedGroupBuilder) {
    if (modifiedGroupBuilder.getMembersCount() == 0) {
      return;
    }

    if (modifiedGroupBuilder.getMembersList().stream().anyMatch(x -> x.getRole() == Role.ADMINISTRATOR)) {
      return;
    }

    List<Member> newMembership = new LinkedList<>();
    for (final Member member : modifiedGroupBuilder.getMembersList()) {
      if (member.getJoinedAtVersion() == actionsBuilder.getVersion()) {
        newMembership.add(member);
        continue;
      }
      ByteString userId = member.getUserId();
      if (actionsBuilder.getModifyMemberRolesList().stream().anyMatch(x -> userId.equals(x.getUserId()))) {
        newMembership.add(member);
        continue;
      }
      actionsBuilder.addModifyMemberRolesBuilder().setRole(Role.ADMINISTRATOR).setUserId(userId);
      newMembership.add(member.toBuilder().setRole(Role.ADMINISTRATOR).build());
    }
    modifiedGroupBuilder.clearMembers().addAllMembers(newMembership);

    if (modifiedGroupBuilder.getMembersList().stream().noneMatch(x -> x.getRole() == Role.ADMINISTRATOR)) {
      // worst case the group has only members who are non-admins and had joined the group this change or had their role
      // edited this change; we have no other option than to subsequently override that portion of the change to ensure
      // at least one admin exists

      newMembership.clear();
      for (final Member member : modifiedGroupBuilder.getMembersList()) {
        actionsBuilder.addModifyMemberRolesBuilder().setRole(Role.ADMINISTRATOR).setUserId(member.getUserId());
        newMembership.add(member.toBuilder().setRole(Role.ADMINISTRATOR).build());
      }
      modifiedGroupBuilder.clearMembers().addAllMembers(newMembership);
    }
  }

  public boolean applyDeleteMembersBanned(GroupUser user, byte[] inviteLinkPassword, Group group, Group.Builder modifiedGroupBuilder, List<DeleteMemberBannedAction> actions) {
    if (actions.isEmpty()) {
      return false;
    }

    if (!GroupAuth.isDeleteMembersBannedAllowed(user, group)) {
      throw new ForbiddenException();
    }

    Set<ByteString> userIdsToRemove = actions.stream().map(GroupChange.Actions.DeleteMemberBannedAction::getDeletedUserId).collect(Collectors.toUnmodifiableSet());

    if (userIdsToRemove.size() != actions.size()) {
      throw new BadRequestException("duplicate user ids in request");
    }

    Set<ByteString> currentUserIds = modifiedGroupBuilder.getMembersBannedList().stream().map(MemberBanned::getUserId).collect(Collectors.toUnmodifiableSet());

    if (!currentUserIds.containsAll(userIdsToRemove)) {
      throw new BadRequestException("some user ids in request are not currently banned");
    }

    List<MemberBanned> membersBanned = modifiedGroupBuilder.getMembersBannedList().stream()
        .filter(memberBanned -> !userIdsToRemove.contains(memberBanned.getUserId()))
        .collect(Collectors.toUnmodifiableList());

    modifiedGroupBuilder.clearMembersBanned().addAllMembersBanned(membersBanned);
    return true;
  }

  public boolean applyAddMembersBanned(GroupUser user, byte[] inviteLinkPassword, Group group, Group.Builder modifiedGroupBuilder, List<AddMemberBannedAction> actions) {
    if (actions.isEmpty()) {
      return false;
    }

    if (!GroupAuth.isAddMembersBannedAllowed(user, group)) {
      throw new ForbiddenException();
    }

    Set<ByteString> userIdsToAdd = actions.stream().map(GroupChange.Actions.AddMemberBannedAction::getAdded).map(MemberBanned::getUserId).collect(Collectors.toUnmodifiableSet());

    if (userIdsToAdd.size() != actions.size()) {
      throw new BadRequestException("duplicate user ids in request");
    }

    if (CollectionUtil.containsAny(userIdsToAdd, modifiedGroupBuilder.getMembersBannedList().stream().map(MemberBanned::getUserId).collect(Collectors.toUnmodifiableSet()))) {
      throw new BadRequestException("some user ids in request already banned");
    }

    actions.stream().map(GroupChange.Actions.AddMemberBannedAction::getAdded).forEach(modifiedGroupBuilder::addMembersBanned);
    return true;
  }
}
