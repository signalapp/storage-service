/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.groups;

import com.google.protobuf.ByteString;
import org.signal.storageservice.auth.GroupUser;
import org.signal.storageservice.storage.protos.groups.AccessControl;
import org.signal.storageservice.storage.protos.groups.AccessControl.AccessRequired;
import org.signal.storageservice.storage.protos.groups.Group;
import org.signal.storageservice.storage.protos.groups.GroupChange.Actions;
import org.signal.storageservice.storage.protos.groups.Member;
import org.signal.storageservice.storage.protos.groups.Member.Role;
import org.signal.storageservice.storage.protos.groups.MemberBanned;
import org.signal.storageservice.storage.protos.groups.MemberPendingAdminApproval;
import org.signal.storageservice.storage.protos.groups.MemberPendingProfileKey;

import java.security.MessageDigest;
import java.util.Iterator;
import java.util.List;
import java.util.Optional;
import java.util.function.Supplier;
import java.util.stream.Stream;

public class GroupAuth {

  public static Optional<Member> getMember(GroupUser user, Group group) {
    for (Member member : group.getMembersList()) {
      if (user.isMember(member, group.getPublicKey())) {
        return Optional.of(member);
      }
    }

    return Optional.empty();
  }

  public static Stream<MemberPendingProfileKey> getMatchingMembersPendingProfileKey(GroupUser user, Group group) {
    return group.getMembersPendingProfileKeyList().stream()
        .filter(member -> user.isMember(member.getMember(), group.getPublicKey()));
  }

  public static Stream<MemberPendingAdminApproval> getMatchingMembersPendingAdminApproval(GroupUser user, Group group) {
    return group.getMembersPendingAdminApprovalList().stream()
        .filter(member -> user.isMember(member.getUserId(), group.getPublicKey()));
  }

  public static Optional<ByteString> selectChangeSource(final GroupUser user, final Group existingGroup, final Supplier<Group> modifiedGroupSupplier) {

    // Members that match user in the existingGroup
    final Iterator<ByteString> matchingSourceIds = Stream.<Supplier<Stream<ByteString>>>of(
            () -> GroupAuth.getMember(user, existingGroup).stream().map(Member::getUserId),
            () -> GroupAuth.getMatchingMembersPendingProfileKey(user, existingGroup).map(pending -> pending.getMember().getUserId()),
            () -> GroupAuth.getMatchingMembersPendingAdminApproval(user, existingGroup).map(MemberPendingAdminApproval::getUserId))
        .flatMap(Supplier::get)
        .iterator();

    // If an ACI is present in the existing group, select that
    ByteString sourceUuid = null;
    while(matchingSourceIds.hasNext()) {
      sourceUuid = matchingSourceIds.next();
      if (user.aciMatches(sourceUuid)) {
        break;
      }
    }
    return Optional
        .ofNullable(sourceUuid)
        .or(() -> {
          // otherwise, the source of the change only appears after the change is made
          final Group modifiedGroup = modifiedGroupSupplier.get();
          return Stream.concat(
                  GroupAuth.getMember(user, modifiedGroup).stream().map(Member::getUserId),
                  GroupAuth.getMatchingMembersPendingAdminApproval(user, modifiedGroup).map(MemberPendingAdminApproval::getUserId))
              .findFirst();
        });
  }

  public static boolean isAccessRequiredOneOf(AccessControl.AccessRequired valueToTest, AccessControl.AccessRequired... acceptableValues) {
    for (AccessControl.AccessRequired acceptableValue : acceptableValues) {
      if (acceptableValue == valueToTest) {
        return true;
      }
    }
    return false;
  }

  public static boolean isMember(GroupUser user, Group group) {
    for (Member member : group.getMembersList()) {
      if (user.isMember(member, group.getPublicKey())) {
        return true;
      }
    }

    return false;
  }

  public static boolean isMemberPendingProfileKey(GroupUser user, Group group) {
    for (MemberPendingProfileKey member : group.getMembersPendingProfileKeyList()) {
      if (user.isMember(member.getMember(), group.getPublicKey())) {
        return true;
      }
    }

    return false;
  }

  public static boolean isMemberPendingAdminApproval(GroupUser user, Group group) {
    for (MemberPendingAdminApproval member : group.getMembersPendingAdminApprovalList()) {
      if (user.isMember(member.getUserId(), group.getPublicKey())) {
        return true;
      }
    }
    return false;
  }

  public static boolean isMemberBanned(GroupUser user, Group group) {
    for (MemberBanned member : group.getMembersBannedList()) {
      if (user.isMember(member.getUserId(), group.getPublicKey())) {
        return true;
      }
    }
    return false;
  }

  public static boolean isAdminstrator(GroupUser user, Group group) {
    for (Member member : group.getMembersList()) {
      if (user.isMember(member, group.getPublicKey())) {
        return member.getRole() == Member.Role.ADMINISTRATOR;
      }
    }

    return false;
  }

  public static boolean isModifyAttributesAllowed(GroupUser user, Group group) {
    Optional<Member> member = getMember(user, group);

    if (member.isEmpty()) {
      return false;
    }

    switch (group.getAccessControl().getAttributes()) {
      case ANY:           return true;
      case MEMBER:        return true;
      case ADMINISTRATOR: return member.get().getRole() == Member.Role.ADMINISTRATOR;
      default:            throw new AssertionError("Unknown role: " + group.getAccessControl().getAttributes().getNumber());
    }
  }

  public static boolean isAddMembersAllowed(GroupUser user, byte[] inviteLinkPassword, Group group, List<Actions.AddMemberAction> actions) {
    Optional<Member> member = getMember(user, group);

    if (member.isPresent()) {
      switch (member.get().getRole()) {
        case ADMINISTRATOR: return true;
        case DEFAULT:       return group.getAccessControl().getMembers() == AccessControl.AccessRequired.MEMBER ||
                                   group.getAccessControl().getMembers() == AccessControl.AccessRequired.ANY;
        default:            throw new AssertionError();
      }
    }

    return (group.getAccessControl().getMembers() == AccessControl.AccessRequired.ANY ||
                (group.getAccessControl().getAddFromInviteLink() == AccessControl.AccessRequired.ANY &&
                 MessageDigest.isEqual(group.getInviteLinkPassword().toByteArray(), inviteLinkPassword))) &&
           actions.size() == 1                                                       &&
           user.isMember(actions.get(0).getAdded(), group.getPublicKey());
  }

  public static boolean isAddMembersPendingProfileKeyAllowed(GroupUser user, Group group) {
    Optional<Member> member = getMember(user, group);

    if (!member.isPresent()) {
      return false;
    }

    return member.get().getRole() == Member.Role.ADMINISTRATOR ||
           group.getAccessControl().getMembers() == AccessControl.AccessRequired.MEMBER ||
           group.getAccessControl().getMembers() == AccessControl.AccessRequired.ANY;
  }

  public static boolean isDeleteMembersAllowed(GroupUser user, Group group, List<Actions.DeleteMemberAction> members) {
    if (isAdminstrator(user, group)) {
      return true;
    }

    return members.size() == 1 && user.isMember(members.get(0).getDeletedUserId(), group.getPublicKey());
  }

  public static boolean isDeleteMembersPendingProfileKeyAllowed(GroupUser user, Group group, List<Actions.DeleteMemberPendingProfileKeyAction> actions) {
    if (isAdminstrator(user, group)) {
      return true;
    }

    return actions.size() == 1 && user.isMember(actions.get(0).getDeletedUserId(), group.getPublicKey());
  }

  public static boolean isModifyAddFromInviteLinkAccessControlAllowed(GroupUser user, Group group) {
    return isAdminstrator(user, group);
  }

  public static boolean isModifyInviteLinkPasswordAllowed(GroupUser user, Group group) {
    return isAdminstrator(user, group);
  }

  public static boolean isModifyAnnouncementsOnlyAllowed(GroupUser user, Group group) {
    return isAdminstrator(user, group);
  }

  public static boolean isAddMembersPendingAdminApprovalAllowed(GroupUser user, byte[] inviteLinkPassword, Group group) {
    return group.getAccessControl().getAddFromInviteLink() == AccessControl.AccessRequired.ADMINISTRATOR &&
            MessageDigest.isEqual(group.getInviteLinkPassword().toByteArray(), inviteLinkPassword);
  }

  public static boolean isDeleteMembersPendingAdminApprovalAllowed(GroupUser user, Group group, List<Actions.DeleteMemberPendingAdminApprovalAction> actions) {
    return isAdminstrator(user, group) || (actions.size() == 1 && user.isMember(actions.get(0).getDeletedUserId(), group.getPublicKey()));
  }

  public static boolean isPromoteMembersPendingAdminApprovalAllowed(GroupUser user, Group group) {
    return isAdminstrator(user, group);
  }

  public static boolean isAllowedToInitiateGroupCall(GroupUser user, Group group) {
    return !group.getAnnouncementsOnly() || isAdminstrator(user, group);
  }

  public static boolean isDeleteMembersBannedAllowed(GroupUser user, Group group) {
    Optional<Member> optionalMember = getMember(user, group);
    if (optionalMember.isEmpty()) {
      return false;
    }
    final Member member = optionalMember.get();
    final Role role = member.getRole();
    switch (role) {
      case ADMINISTRATOR: return true;
      case DEFAULT: return isAccessRequiredOneOf(group.getAccessControl().getMembers(), AccessRequired.MEMBER, AccessRequired.ANY);
      default: return false;
    }
  }

  public static boolean isAddMembersBannedAllowed(GroupUser user, Group group) {
    return isAdminstrator(user, group);
  }
}
