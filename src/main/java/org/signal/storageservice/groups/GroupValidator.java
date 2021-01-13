/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.groups;

import com.google.protobuf.ByteString;
import org.apache.commons.codec.binary.Base64;
import org.signal.storageservice.auth.GroupUser;
import org.signal.storageservice.configuration.GroupConfiguration;
import org.signal.storageservice.controllers.GroupsController;
import org.signal.storageservice.storage.protos.groups.AccessControl;
import org.signal.storageservice.storage.protos.groups.Group;
import org.signal.storageservice.storage.protos.groups.GroupChange;
import org.signal.storageservice.storage.protos.groups.Member;
import org.signal.storageservice.storage.protos.groups.MemberPendingAdminApproval;
import org.signal.storageservice.storage.protos.groups.MemberPendingProfileKey;
import org.signal.storageservice.util.CollectionUtil;
import org.signal.zkgroup.InvalidInputException;
import org.signal.zkgroup.VerificationFailedException;
import org.signal.zkgroup.groups.GroupPublicParams;
import org.signal.zkgroup.profiles.ProfileKeyCredentialPresentation;
import org.signal.zkgroup.profiles.ServerZkProfileOperations;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.ws.rs.BadRequestException;
import javax.ws.rs.ForbiddenException;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

public class GroupValidator {
  private static final int INVITE_LINK_PASSWORD_SIZE_BYTES = 16;
  private final Logger logger = LoggerFactory.getLogger(GroupsController.class);

  private final ServerZkProfileOperations profileOperations;
  private final int maxGroupSize;
  private final int maxGroupTitleLengthBytes;

  public GroupValidator(ServerZkProfileOperations profileOperations, GroupConfiguration groupConfiguration) {
    this.profileOperations = profileOperations;
    this.maxGroupSize = groupConfiguration.getMaxGroupSize();
    this.maxGroupTitleLengthBytes = groupConfiguration.getMaxGroupTitleLengthBytes();
  }

  public Member validateMember(Group group, Member member) throws BadRequestException {
    try {
      if (member.getRole() == Member.Role.UNRECOGNIZED ||
              member.getRole() == Member.Role.UNKNOWN) {
        throw new BadRequestException("Unknown member role");
      }

      if (member.getPresentation().isEmpty()) {
        throw new BadRequestException("Missing presentation");
      }

      GroupPublicParams                publicParams                     = new GroupPublicParams(group.getPublicKey().toByteArray());
      ProfileKeyCredentialPresentation profileKeyCredentialPresentation = new ProfileKeyCredentialPresentation(member.getPresentation().toByteArray());

      profileOperations.verifyProfileKeyCredentialPresentation(publicParams, profileKeyCredentialPresentation);

      return member.toBuilder()
                   .clearPresentation()
                   .setProfileKey(ByteString.copyFrom(profileKeyCredentialPresentation.getProfileKeyCiphertext().serialize()))
                   .setUserId(ByteString.copyFrom(profileKeyCredentialPresentation.getUuidCiphertext().serialize()))
                   .setJoinedAtVersion(group.getVersion())
                   .build();
    } catch (InvalidInputException | VerificationFailedException e) {
      logger.info("Member validation", e);
      throw new BadRequestException(e);
    }
  }

  public MemberPendingProfileKey validateMemberPendingProfileKey(Member addedBy, Group group, MemberPendingProfileKey memberPendingProfileKey)
          throws BadRequestException {
    if (!memberPendingProfileKey.hasMember() || memberPendingProfileKey.getMember() == null) {
      throw new BadRequestException("Missing member");
    }

    if (memberPendingProfileKey.getMember().getUserId() == null || memberPendingProfileKey.getMember().getUserId().isEmpty()) {
      throw new BadRequestException("Missing member user id");
    }

    if (memberPendingProfileKey.getMember().getRole() == Member.Role.UNKNOWN || memberPendingProfileKey.getMember().getRole() == Member.Role.UNRECOGNIZED) {
      throw new BadRequestException("Unknown member role");
    }

    if (memberPendingProfileKey.getMember().getPresentation() != null && !memberPendingProfileKey.getMember().getPresentation().isEmpty()) {
      throw new BadRequestException("There's a presentation for a pending member");
    }

    if (memberPendingProfileKey.getMember().getProfileKey() != null && !memberPendingProfileKey.getMember().getProfileKey().isEmpty()) {
      throw new BadRequestException("There's a profile key for a pending member");
    }

    Member.Builder memberPendingProfileKeyData = memberPendingProfileKey.getMember().toBuilder();
    memberPendingProfileKeyData.setJoinedAtVersion(group.getVersion());
    memberPendingProfileKeyData.clearPresentation();
    memberPendingProfileKeyData.clearProfileKey();

    return MemberPendingProfileKey.newBuilder()
                                  .setMember(memberPendingProfileKeyData)
                                  .setAddedByUserId(addedBy.getUserId())
                                  .setTimestamp(System.currentTimeMillis())
                                  .build();
  }

  public MemberPendingAdminApproval validateMemberPendingAdminApproval(GroupUser user, Group group, MemberPendingAdminApproval memberPendingAdminApproval) throws BadRequestException {
    try {
      if (!memberPendingAdminApproval.getUserId().isEmpty()) {
        throw new BadRequestException("user id should not be set in request");
      }

      if (!memberPendingAdminApproval.getProfileKey().isEmpty()) {
        throw new BadRequestException("profile key should not be set in request");
      }

      if (memberPendingAdminApproval.getPresentation().isEmpty()) {
        throw new BadRequestException("missing presentation in request");
      }

      if (memberPendingAdminApproval.getTimestamp() != 0L) {
        throw new BadRequestException("timestamp should not be set in request");
      }

      GroupPublicParams                publicParams                     = new GroupPublicParams(group.getPublicKey().toByteArray());
      ProfileKeyCredentialPresentation profileKeyCredentialPresentation = new ProfileKeyCredentialPresentation(memberPendingAdminApproval.getPresentation().toByteArray());
      profileOperations.verifyProfileKeyCredentialPresentation(publicParams, profileKeyCredentialPresentation);

      if (!user.isMember(ByteString.copyFrom(profileKeyCredentialPresentation.getUuidCiphertext().serialize()), group.getPublicKey())) {
        throw new BadRequestException("cannot add others to a group using an invite link");
      }

      return MemberPendingAdminApproval.newBuilder()
                                       .setProfileKey(ByteString.copyFrom(profileKeyCredentialPresentation.getProfileKeyCiphertext().serialize()))
                                       .setUserId(ByteString.copyFrom(profileKeyCredentialPresentation.getUuidCiphertext().serialize()))
                                       .setTimestamp(System.currentTimeMillis())
                                       .build();
    } catch (VerificationFailedException | InvalidInputException e) {
      throw new BadRequestException("invalid presentation", e);
    }
  }

  public List<GroupChange.Actions.AddMemberAction> validateAddMember(GroupUser user, byte[] inviteLinkPassword, Group group, List<GroupChange.Actions.AddMemberAction> actions) throws BadRequestException {
    List<GroupChange.Actions.AddMemberAction> validatedActions = new LinkedList<>();

    for (GroupChange.Actions.AddMemberAction action : actions) {
      if (!action.hasAdded() || action.getAdded().getPresentation() == null || action.getAdded().getPresentation().isEmpty()) {
        throw new BadRequestException("Bad member construction");
      }

      if (action.getJoinFromInviteLink()) {
        throw new BadRequestException("Invalid field set on action");
      }

      final GroupChange.Actions.AddMemberAction.Builder builder = action.toBuilder().setAdded(validateMember(group, action.getAdded()));
      if (!GroupAuth.isMember(user, group)
              && user.isMember(builder.getAdded().getUserId(), group.getPublicKey())
              && group.getAccessControl().getMembers() != AccessControl.AccessRequired.ANY
              && group.getAccessControl().getAddFromInviteLink() == AccessControl.AccessRequired.ANY
              && MessageDigest.isEqual(group.getInviteLinkPassword().toByteArray(), inviteLinkPassword)) {
        builder.setJoinFromInviteLink(true);
      }
      validatedActions.add(builder.build());
    }

    return validatedActions;
  }

  public List<GroupChange.Actions.AddMemberPendingProfileKeyAction> validateAddMembersPendingProfileKey(GroupUser addedByUser, Group group, List<GroupChange.Actions.AddMemberPendingProfileKeyAction> actions)
          throws BadRequestException, ForbiddenException {
    if (actions.isEmpty()) {
      return actions;
    }

    Member addedBy = GroupAuth.getMember(addedByUser, group).orElseThrow(ForbiddenException::new);

    List<GroupChange.Actions.AddMemberPendingProfileKeyAction> validatedActions = new LinkedList<>();

    for (GroupChange.Actions.AddMemberPendingProfileKeyAction action : actions) {
      if (!action.hasAdded() || !action.getAdded().hasMember()) {
        throw new BadRequestException("Bad member construction");
      }

      validatedActions.add(action.toBuilder().setAdded(validateMemberPendingProfileKey(addedBy, group, action.getAdded())).build());
    }

    return validatedActions;
  }

  public List<GroupChange.Actions.AddMemberPendingAdminApprovalAction> validateAddMembersPendingAdminApproval(GroupUser user, byte[] inviteLinkPassword, Group group, List<GroupChange.Actions.AddMemberPendingAdminApprovalAction> actions) {
    if (actions.isEmpty()) {
      return actions;
    }

    if (!MessageDigest.isEqual(inviteLinkPassword, group.getInviteLinkPassword().toByteArray())) {
      throw new ForbiddenException();
    }

    List<GroupChange.Actions.AddMemberPendingAdminApprovalAction> validatedActions = new ArrayList<>(actions.size());
    for (GroupChange.Actions.AddMemberPendingAdminApprovalAction action : actions) {
      if (!action.hasAdded()) {
        throw new BadRequestException("missing added field in add members pending admin approval actions");
      }
      validatedActions.add(GroupChange.Actions.AddMemberPendingAdminApprovalAction.newBuilder()
                                                                                  .setAdded(validateMemberPendingAdminApproval(user, group, action.getAdded()))
                                                                                  .build());
    }
    return validatedActions;
  }

  public ProfileKeyCredentialPresentation validatePresentationUpdate(GroupUser source, Group group, ByteString presentationData) throws BadRequestException, ForbiddenException {
    try {
      GroupPublicParams publicParams = new GroupPublicParams(group.getPublicKey().toByteArray());

      if (presentationData == null || presentationData.isEmpty()) {
        throw new BadRequestException();
      }

      ProfileKeyCredentialPresentation presentation = new ProfileKeyCredentialPresentation(presentationData.toByteArray());

      if (!source.isMember(ByteString.copyFrom(presentation.getUuidCiphertext().serialize()), group.getPublicKey())) {
        throw new ForbiddenException();
      }

      profileOperations.verifyProfileKeyCredentialPresentation(publicParams, presentation);

      return presentation;
    } catch (InvalidInputException | VerificationFailedException e) {
      throw new BadRequestException(e);
    }
  }

  public boolean isValidAvatarUrl(String url, ByteString groupId) {
    if (url == null || url.isEmpty()) return true;

    if (!url.startsWith("groups/" + Base64.encodeBase64URLSafeString(groupId.toByteArray()) + "/")) {
      return false;
    }

    String[] parts = url.split("[/]");

    if (parts.length != 3) {
      return false;
    }

    byte[] object = Base64.decodeBase64(parts[2]);

    return object.length == 16;
  }

  public void validateFinalGroupState(Group group) throws BadRequestException {
    if (group.getTitle().isEmpty()) {
      throw new BadRequestException("group title must be non-empty");
    }

    if (group.getTitle().size() > maxGroupTitleLengthBytes) {
      throw new BadRequestException("group title length exceeded");
    }

    if (!group.getInviteLinkPassword().isEmpty() && group.getInviteLinkPassword().size() != INVITE_LINK_PASSWORD_SIZE_BYTES) {
      throw new BadRequestException("group invite link password cannot be set to invalid size");
    }

    if (group.getInviteLinkPassword().isEmpty() &&
        group.getAccessControl().getAddFromInviteLink() != AccessControl.AccessRequired.UNSATISFIABLE &&
        group.getAccessControl().getAddFromInviteLink() != AccessControl.AccessRequired.UNKNOWN) {
      throw new BadRequestException("group cannot permit joining with no password");
    }

    // the admin approval pending list was purposefully left out of this computation
    if (group.getMembersCount() + group.getMembersPendingProfileKeyCount() > maxGroupSize) {
      throw new BadRequestException("group size cannot exceed " + maxGroupSize);
    }

    Set<ByteString> membersUserIds = group.getMembersList().stream().map(Member::getUserId).collect(Collectors.toSet());
    Set<ByteString> membersPendingProfileKeyUserIds = group.getMembersPendingProfileKeyList().stream().map(member -> member.getMember().getUserId()).collect(Collectors.toSet());
    Set<ByteString> membersPendingAdminApprovalUserIds = group.getMembersPendingAdminApprovalList().stream().map(MemberPendingAdminApproval::getUserId).collect(Collectors.toSet());

    if (membersUserIds.size() != group.getMembersCount() ||
        membersPendingProfileKeyUserIds.size() != group.getMembersPendingProfileKeyCount() ||
        membersPendingAdminApprovalUserIds.size() != group.getMembersPendingAdminApprovalCount()) {
      throw new BadRequestException("group cannot contain duplicate user ids in the membership lists");
    }

    if (CollectionUtil.containsAny(membersUserIds, membersPendingProfileKeyUserIds) ||
        CollectionUtil.containsAny(membersUserIds, membersPendingAdminApprovalUserIds) ||
        CollectionUtil.containsAny(membersPendingProfileKeyUserIds, membersPendingAdminApprovalUserIds)) {
      throw new BadRequestException("group cannot contain the same user in multiple membership lists");
    }

    validateAccessControl(group);
    validateRoles(group);
  }

  private void validateAccessControl(Group group) throws BadRequestException {
    final AccessControl accessControl = group.getAccessControl();

    if (!GroupAuth.isAccessRequiredOneOf(accessControl.getAttributes(), AccessControl.AccessRequired.UNKNOWN, AccessControl.AccessRequired.ADMINISTRATOR, AccessControl.AccessRequired.MEMBER)) {
      throw new BadRequestException("attribute access invalid");
    }

    if (!GroupAuth.isAccessRequiredOneOf(accessControl.getMembers(), AccessControl.AccessRequired.UNKNOWN, AccessControl.AccessRequired.ADMINISTRATOR, AccessControl.AccessRequired.MEMBER)) {
      throw new BadRequestException("members access invalid");
    }

    if (!GroupAuth.isAccessRequiredOneOf(accessControl.getAddFromInviteLink(), AccessControl.AccessRequired.UNKNOWN, AccessControl.AccessRequired.ANY, AccessControl.AccessRequired.ADMINISTRATOR, AccessControl.AccessRequired.UNSATISFIABLE)) {
      throw new BadRequestException("add from invite link access invalid");
    }
  }

  private void validateRoles(Group group) throws BadRequestException {
    for (Member member : group.getMembersList()) {
      final Member.Role role = member.getRole();
      if (role != Member.Role.DEFAULT && role != Member.Role.ADMINISTRATOR) {
        throw new BadRequestException("invalid member role");
      }
    }

    for (MemberPendingProfileKey member : group.getMembersPendingProfileKeyList()) {
      final Member.Role role = member.getMember().getRole();
      if (role != Member.Role.DEFAULT && role != Member.Role.ADMINISTRATOR) {
        throw new BadRequestException("invalid member pending profile key role");
      }
    }
  }
}
