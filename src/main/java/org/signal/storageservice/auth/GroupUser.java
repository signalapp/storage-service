/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.auth;

import com.google.protobuf.ByteString;
import org.signal.storageservice.storage.protos.groups.Member;
import org.signal.zkgroup.InvalidInputException;
import org.signal.zkgroup.groups.GroupPublicParams;

import javax.security.auth.Subject;
import java.security.MessageDigest;
import java.security.Principal;

public class GroupUser implements Principal {

  private final ByteString userCiphertext;
  private final ByteString groupPublicKey;
  private final ByteString groupId;

  GroupUser(ByteString userCiphertext, ByteString groupPublicKey, ByteString groupId) {
    this.userCiphertext  = userCiphertext;
    this.groupPublicKey  = groupPublicKey;
    this.groupId         = groupId;
  }

  public boolean isMember(Member member, ByteString groupPublicKey) {
    return isMember(member.getUserId(), groupPublicKey);
  }

  public boolean isMember(ByteString uuid, ByteString groupPublicKey) {
    return MessageDigest.isEqual(this.groupPublicKey.toByteArray(), groupPublicKey.toByteArray()) &&
            MessageDigest.isEqual(this.userCiphertext.toByteArray(), uuid.toByteArray());
  }

  public GroupPublicParams getGroupPublicKey() {
    try {
      return new GroupPublicParams(groupPublicKey.toByteArray());
    } catch (InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public ByteString getGroupId() {
    return groupId;
  }

  // Principal implementation

  @Override
  public String getName() {
    return null;
  }

  @Override
  public boolean implies(Subject subject) {
    return false;
  }

  @Override
  public boolean equals(Object other) {
    if (other == null || !(other instanceof GroupUser)) return false;

    GroupUser that = (GroupUser)other;

    return this.userCiphertext.equals(that.userCiphertext) &&
           this.groupPublicKey.equals(that.groupPublicKey);
  }

  @Override
  public int hashCode() {
    return userCiphertext.hashCode() ^ groupPublicKey.hashCode();
  }
}
