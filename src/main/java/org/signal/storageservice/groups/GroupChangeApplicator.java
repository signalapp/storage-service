/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.groups;

import com.google.common.annotations.VisibleForTesting;
import com.google.protobuf.ByteString;
import jakarta.ws.rs.BadRequestException;
import jakarta.ws.rs.ForbiddenException;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.signal.storageservice.auth.GroupUser;
import org.signal.storageservice.storage.protos.groups.AccessControl;
import org.signal.storageservice.storage.protos.groups.Group;
import org.signal.storageservice.storage.protos.groups.GroupChange;
import org.signal.storageservice.storage.protos.groups.GroupChange.Actions;
import org.signal.storageservice.storage.protos.groups.GroupChange.Actions.AddMemberBannedAction;
import org.signal.storageservice.storage.protos.groups.GroupChange.Actions.DeleteMemberBannedAction;
import org.signal.storageservice.storage.protos.groups.GroupChange.Actions.ModifyMemberLabelAction;
import org.signal.storageservice.storage.protos.groups.GroupChange.Actions.PromoteMemberPendingPniAciProfileKeyAction;
import org.signal.storageservice.storage.protos.groups.Member;
import org.signal.storageservice.storage.protos.groups.Member.Role;
import org.signal.storageservice.storage.protos.groups.MemberBanned;
import org.signal.storageservice.storage.protos.groups.MemberPendingAdminApproval;
import org.signal.storageservice.storage.protos.groups.MemberPendingProfileKey;
import org.signal.storageservice.util.CollectionUtil;

public class GroupChangeApplicator {
  private final GroupValidator groupValidator;

  @VisibleForTesting public static final int MAX_LABEL_EMOJI_CIPHERTEXT_LENGTH = 64;
  @VisibleForTesting public static final int MAX_LABEL_STRING_CIPHERTEXT_LENGTH = 512;

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

    if (addMembers.stream().anyMatch(member -> member.getAdded().getRole() == Member.Role.ADMINISTRATOR) && !GroupAuth.isAdministrator(user, group)) {
      throw new ForbiddenException();
    }

    if (CollectionUtil.containsDuplicates(addMembers.stream().map(action -> action.getAdded().getUserId()).collect(Collectors.toList()))) {
      throw new BadRequestException("duplicate group members in to-add list");
    }

    if (CollectionUtil.containsAny(group.getMembersList().stream().map(Member::getUserId).collect(Collectors.toList()),
                                   addMembers.stream().map(action -> action.getAdded().getUserId()).collect(Collectors.toList()))) {
      throw new BadRequestException("adding member already in group");
    }

    for (GroupChange.Actions.AddMemberAction action : addMembers) {
      final ByteString userId = action.getAdded().getUserId();
      if (userId == null || userId.isEmpty()) {
        throw new BadRequestException("adding member with no userid");
      }

      if (action.getAdded().getProfileKey() == null || action.getAdded().getProfileKey().isEmpty()) {
        throw new BadRequestException("adding member with no profile key");
      }

      if (action.getAdded().getRole() == Member.Role.UNKNOWN || action.getAdded().getRole() == Member.Role.UNRECOGNIZED) {
        throw new BadRequestException("adding member with unrecognized role");
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
      throw new BadRequestException("duplicate group members in to-delete list");
    }

    if (!GroupAuth.isDeleteMembersAllowed(user, group, deleteMembers)) {
      throw new ForbiddenException();
    }

    Set<ByteString> currentMemberUuids = modifiedGroupBuilder.getMembersList().stream().map(Member::getUserId).collect(Collectors.toSet());
    Set<ByteString> deleteMemberUuids  = deleteMembers.stream().map(GroupChange.Actions.DeleteMemberAction::getDeletedUserId).collect(Collectors.toSet());

    if (!currentMemberUuids.containsAll(deleteMemberUuids)) {
      throw new BadRequestException("deleting user not present in group");
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
      throw new BadRequestException("modifying user with no userid");
    }

    if (modifyMembers.stream().anyMatch(modify -> modify.getRole() == Member.Role.UNKNOWN || modify.getRole() == Member.Role.UNRECOGNIZED)) {
      throw new BadRequestException("modifying user with unrecognized role");
    }

    if (CollectionUtil.containsDuplicates(modifyMembers.stream().map(GroupChange.Actions.ModifyMemberRoleAction::getUserId).collect(Collectors.toList()))) {
      throw new BadRequestException("duplicate members in to-modify list");
    }

    if (!GroupAuth.isAdministrator(user, group)) {
      throw new ForbiddenException();
    }

    if (!modifiedGroupBuilder.getMembersList().stream().map(Member::getUserId).collect(Collectors.toSet())
                             .containsAll(modifyMembers.stream().map(GroupChange.Actions.ModifyMemberRoleAction::getUserId).collect(Collectors.toList()))) {
      throw new BadRequestException("modifying user not in group");
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

  public void applyModifyMemberLabel(GroupUser user, Group group, Group.Builder modifiedGroupBuilder, List<ModifyMemberLabelAction> modifyMemberLabels)
          throws BadRequestException, ForbiddenException {
    final Member.Role userRole = GroupAuth.getMember(user, group).orElseThrow(() -> new ForbiddenException()).getRole();

    final Map<ByteString, Member.Builder> memberBuilders = modifiedGroupBuilder.getMembersBuilderList().stream()
        .collect(Collectors.toMap(Member.Builder::getUserId, Function.identity()));

    for (ModifyMemberLabelAction modifyMemberLabel : modifyMemberLabels) {
      if (modifyMemberLabel.getUserId().isEmpty()) {
        throw new BadRequestException("modifying user with no userid");
      }

      if (modifyMemberLabel.getLabelString().isEmpty() && !modifyMemberLabel.getLabelEmoji().isEmpty()) {
        throw new BadRequestException("label emoji must be accompanied by a label string");
      }

      if (modifyMemberLabel.getLabelEmoji().size() > MAX_LABEL_EMOJI_CIPHERTEXT_LENGTH) {
        throw new BadRequestException("label emoji ciphertext too long");
      }

      if (modifyMemberLabel.getLabelString().size() > MAX_LABEL_STRING_CIPHERTEXT_LENGTH) {
        throw new BadRequestException("label string ciphertext too long");
      }

      // can only modify your own labels unless you are an administrator, in which case you can clear others'
      if (!GroupAuth.isModifyMemberLabelAllowed(
          group, userRole, user.aciMatches(modifyMemberLabel.getUserId()), modifyMemberLabel.getLabelString().isEmpty())) {
        throw new ForbiddenException();
      }

      // can only modify labels of users in group
      if (!memberBuilders.containsKey(modifyMemberLabel.getUserId())) {
        throw new ForbiddenException("modifying user not in group");
      }

      memberBuilders.get(modifyMemberLabel.getUserId())
          .setLabelEmoji(modifyMemberLabel.getLabelEmoji())
          .setLabelString(modifyMemberLabel.getLabelString());
    }
  }

  public void applyModifyMemberProfileKeys(GroupUser user, byte[] inviteLinkPassword, Group group, Group.Builder modifiedGroupBuilder, List<GroupChange.Actions.ModifyMemberProfileKeyAction> modifyMembers)
          throws BadRequestException, ForbiddenException {
    if (modifyMembers.isEmpty()) {
      return;
    }

    for (GroupChange.Actions.ModifyMemberProfileKeyAction action : modifyMembers) {
      // copy: if a RepeatedFieldBuilder is installed (e.g. by applyModifyMemberLabel), getMembersList() is a live view
      // that clearMembers() below would empty before the replacement list is built
      List<Member> currentMembers = List.copyOf(modifiedGroupBuilder.getMembersList());
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
            !GroupAuth.isAdministrator(user, group)) {
      throw new ForbiddenException();
    }

    if (CollectionUtil.containsDuplicates(addMembersPendingProfileKey.stream().map(pending -> pending.getAdded().getMember().getUserId()).collect(Collectors.toList()))) {
      throw new BadRequestException("duplicate members in add-pending-profile-key list");
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
        throw new BadRequestException("adding member pending profile id with unrecognized role");
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
      throw new BadRequestException("duplicate members pending profile key in to-delete list");
    }

    if (!GroupAuth.isDeleteMembersPendingProfileKeyAllowed(user, group, deleteMembersPendingProfileKey)) {
      throw new ForbiddenException();
    }

    Set<ByteString> currentMembersPendingProfileKeyUuids = modifiedGroupBuilder.getMembersPendingProfileKeyList().stream().map(pending -> pending.getMember().getUserId()).collect(Collectors.toSet());
    Set<ByteString> deleteMembersPendingProfileKeyUuids  = deleteMembersPendingProfileKey.stream().map(GroupChange.Actions.DeleteMemberPendingProfileKeyAction::getDeletedUserId).collect(Collectors.toSet());

    if (!currentMembersPendingProfileKeyUuids.containsAll(deleteMembersPendingProfileKeyUuids)) {
      throw new BadRequestException("deleting member pending profile id not present in group");
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

  public void applyPromoteMembersPendingPniAciProfileKey(Group group, Group.Builder modifiedGroupBuilder, GroupChange.Actions.Builder actionsBuilder)
      throws BadRequestException, ForbiddenException {

    final LinkedHashMap<ByteString, MemberPendingProfileKey> membersPendingProfileKey =
      modifiedGroupBuilder.getMembersPendingProfileKeyList()
        .stream()
        .sequential()
        .collect(Collectors.toMap(mppk -> mppk.getMember().getUserId(), Function.identity(), (a, b) -> a, LinkedHashMap::new));

    final LinkedHashMap<ByteString, MemberBanned> membersBanned = modifiedGroupBuilder.getMembersBannedList()
      .stream()
      .sequential()
      .collect(Collectors.toMap(MemberBanned::getUserId, Function.identity(), (a, b) -> a, LinkedHashMap::new));

    final Collection<PromoteMemberPendingPniAciProfileKeyAction> membersToPromote =
      actionsBuilder.getPromoteMembersPendingPniAciProfileKeyList()
        .stream()
        .filter(action -> membersPendingProfileKey.containsKey(action.getPni()))
        .collect(Collectors.toUnmodifiableMap(PromoteMemberPendingPniAciProfileKeyAction::getPni, Function.identity(), (a, b) -> a))
        .values();

    // this could fail due to either duplicates or attempting to promote a member that wasn't pending by PNI
    if (membersToPromote.size() != actionsBuilder.getPromoteMembersPendingPniAciProfileKeyCount()) {
      throw new ForbiddenException();
    }

    final int newVersion = group.getVersion() + 1;
    membersToPromote.forEach(action -> {
      final ByteString aci = action.getUserId();

      // the PNI is no longer a pending member
      final MemberPendingProfileKey pendingMember = membersPendingProfileKey.remove(action.getPni());

      // the pending member becomes the new member
      modifiedGroupBuilder.addMembers(
        pendingMember.getMember()
          .toBuilder()
          .clearPresentation()
          .setUserId(aci)
          .setProfileKey(action.getProfileKey())
          .setJoinedAtVersion(newVersion));

      // if they were also pending by ACI, that's also no longer  the case, but we don't add them a second time
      membersPendingProfileKey.remove(aci);

      // they can't have been banned by PNI because we enforce that a member
      // can't be both pending and banned, but their ACI might have been
      // banned, in which case we need to generate a synthetic unban
      if (membersBanned.containsKey(aci)) {
        actionsBuilder.addDeleteMembersBanned(DeleteMemberBannedAction.newBuilder().setDeletedUserId(aci));
        membersBanned.remove(aci);
      }
    });

    modifiedGroupBuilder.clearMembersPendingProfileKey().addAllMembersPendingProfileKey(membersPendingProfileKey.values());
    if (membersBanned.size() != modifiedGroupBuilder.getMembersBannedCount()) {
      modifiedGroupBuilder.clearMembersBanned().addAllMembersBanned(membersBanned.values());
    }
  }

  public void applyModifyTitle(GroupUser user, byte[] inviteLinkPassword, Group group, Group.Builder modifiedGroupBuilder, GroupChange.Actions.ModifyTitleAction modifyTitle)
          throws ForbiddenException, BadRequestException {
    if (modifyTitle == null) {
      return;
    }

    if (modifyTitle.getTitle() == null || modifyTitle.getTitle().isEmpty()) {
      throw new BadRequestException("setting empty group title");
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
      throw new BadRequestException("invalid avatar url");
    }

    modifiedGroupBuilder.setAvatarUrl(modifyAvatar.getAvatar());
  }

  public void applyModifyDisappearingMessageTimer(GroupUser user, byte[] inviteLinkPassword, Group group, Group.Builder modifiedGroupBuilder, GroupChange.Actions.ModifyDisappearingMessageTimerAction modifyDisappearingMessageTimer)
          throws ForbiddenException {
    if (modifyDisappearingMessageTimer == null) {
      return;
    }

    if (!groupValidator.isValidModifyDisappearingMessageTimerAction(modifyDisappearingMessageTimer)) {
      throw new BadRequestException("disappearing messages timer length exceeded");
    }

    if (!GroupAuth.isModifyAttributesAllowed(user, group)) {
      throw new ForbiddenException();
    }

    modifiedGroupBuilder.setDisappearingMessagesTimer(modifyDisappearingMessageTimer.getTimer());
  }

  public void applyModifyAttributesAccess(GroupUser user, byte[] inviteLinkPassword, Group group, Group.Builder modifiedGroupBuilder, GroupChange.Actions.ModifyAttributesAccessControlAction modifyAttributesAccess) throws ForbiddenException, BadRequestException {
    if (modifyAttributesAccess == null || !modifyAttributesAccess.isInitialized()) {
      throw new BadRequestException("invalid modify-attributes-access proto");
    }

    if (modifyAttributesAccess.getAttributesAccess() != AccessControl.AccessRequired.ADMINISTRATOR &&
        modifyAttributesAccess.getAttributesAccess() != AccessControl.AccessRequired.MEMBER) {
      throw new BadRequestException("illegal attributes-access setting");
    }

    if (!GroupAuth.isAdministrator(user, group)) {
      throw new ForbiddenException();
    }

    modifiedGroupBuilder.setAccessControl(modifiedGroupBuilder.getAccessControlBuilder().setAttributes(modifyAttributesAccess.getAttributesAccess()));
  }

  public void applyModifyMembersAccess(GroupUser user, byte[] inviteLinkPassword, Group group, Group.Builder modifiedGroupBuilder, GroupChange.Actions.ModifyMembersAccessControlAction modifyMembersAccess) throws ForbiddenException, BadRequestException {
    if (modifyMembersAccess == null || !modifyMembersAccess.isInitialized()) {
      throw new BadRequestException("invalid modify-members-access proto");
    }

    if (modifyMembersAccess.getMembersAccess() != AccessControl.AccessRequired.ADMINISTRATOR &&
        modifyMembersAccess.getMembersAccess() != AccessControl.AccessRequired.MEMBER) {
      throw new BadRequestException("illegal modify-members-access setting");
    }

    if (!GroupAuth.isAdministrator(user, group)) {
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
      throw new BadRequestException("illegal add-from-invite-link-access setting");
    }

    modifiedGroupBuilder.setAccessControl(modifiedGroupBuilder.getAccessControlBuilder().setAddFromInviteLink(action.getAddFromInviteLinkAccess()));
  }

  public void applyModifyMemberLabelAccess(GroupUser user, Group group, Group.Builder modifiedGroupBuilder, GroupChange.Actions.ModifyMemberLabelAccessControlAction action) throws ForbiddenException, BadRequestException {
    if (!GroupAuth.isModifyMemberLabelAccessControlAllowed(user, group)) {
      throw new ForbiddenException();
    }

    if (action.getMemberLabelAccess() != AccessControl.AccessRequired.MEMBER &&
        action.getMemberLabelAccess() != AccessControl.AccessRequired.ADMINISTRATOR) {
      throw new BadRequestException("illegal member-label-access setting");
    }

    modifiedGroupBuilder.setAccessControl(modifiedGroupBuilder.getAccessControlBuilder().setMemberLabel(action.getMemberLabelAccess()));
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

  public void applyTerminateGroup(GroupUser user, Group group, Group.Builder modifiedGroupBuilder) {
    if (!GroupAuth.isAdministrator(user, group)) {
      throw new ForbiddenException();
    }
    modifiedGroupBuilder.setTerminated(true);
  }
}
