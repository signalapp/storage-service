/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.auth;

import com.google.common.annotations.VisibleForTesting;
import com.google.protobuf.ByteString;
import org.signal.storageservice.storage.protos.groups.Member;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.groups.GroupPublicParams;

import javax.annotation.Nullable;
import javax.security.auth.Subject;
import java.security.MessageDigest;
import java.security.Principal;
import java.util.Optional;

public class GroupUser implements Principal {

  private final ByteString aciCiphertext;
  private final ByteString groupPublicKey;
  private final ByteString groupId;

  @Nullable
  private final ByteString pniCiphertext;

  public GroupUser(ByteString aciCiphertext, @Nullable ByteString pniCiphertext, ByteString groupPublicKey, ByteString groupId) {
    this.aciCiphertext = aciCiphertext;
    this.pniCiphertext = pniCiphertext;
    this.groupPublicKey = groupPublicKey;
    this.groupId = groupId;
  }

  public boolean isMember(Member member, ByteString groupPublicKey) {
    return isMember(member.getUserId(), groupPublicKey);
  }

  public boolean aciMatches(ByteString uuid) {
    return MessageDigest.isEqual(this.aciCiphertext.toByteArray(), uuid.toByteArray());
  }

  public boolean isMember(ByteString uuid, ByteString groupPublicKey) {
    final boolean publicKeyMatches = MessageDigest.isEqual(this.groupPublicKey.toByteArray(), groupPublicKey.toByteArray());
    final boolean aciMatches = MessageDigest.isEqual(this.aciCiphertext.toByteArray(), uuid.toByteArray());
    final boolean pniMatches =
        pniCiphertext != null && MessageDigest.isEqual(this.pniCiphertext.toByteArray(), uuid.toByteArray());

    return publicKeyMatches && (aciMatches || pniMatches);
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

  @VisibleForTesting
  ByteString getAciCiphertext() {
    return aciCiphertext;
  }

  public Optional<ByteString> getPniCiphertext() {
    return Optional.ofNullable(pniCiphertext);
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
}
