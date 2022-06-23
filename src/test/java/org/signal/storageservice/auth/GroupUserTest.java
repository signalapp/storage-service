/*
 * Copyright 2013-2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.auth;

import com.google.protobuf.ByteString;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.SecureRandom;
import java.util.Random;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class GroupUserTest {

  @ParameterizedTest
  @MethodSource
  void isMember(final ByteString userAci,
      final ByteString userPni,
      final ByteString userPublicKey,
      final ByteString memberUuid,
      final ByteString groupPublicKey,
      final boolean expectIsMember) {

    final GroupUser groupUser = new GroupUser(userAci, userPni, userPublicKey, generateRandomByteString());

    assertEquals(expectIsMember, groupUser.isMember(memberUuid, groupPublicKey));
  }

  private static Stream<Arguments> isMember() {
    final ByteString memberUuid = generateRandomByteString();
    final ByteString groupPublicKey = generateRandomByteString();

    return Stream.of(
        Arguments.of(memberUuid, generateRandomByteString(), groupPublicKey, memberUuid, groupPublicKey, true),
        Arguments.of(memberUuid, null, groupPublicKey, memberUuid, groupPublicKey, true),
        Arguments.of(generateRandomByteString(), memberUuid, groupPublicKey, memberUuid, groupPublicKey, true),
        Arguments.of(generateRandomByteString(), null, groupPublicKey, memberUuid, groupPublicKey, false),
        Arguments.of(generateRandomByteString(), generateRandomByteString(), groupPublicKey, memberUuid, groupPublicKey, false),
        Arguments.of(memberUuid, null, generateRandomByteString(), memberUuid, groupPublicKey, false)
    );
  }

  private static ByteString generateRandomByteString() {
    final Random random = new Random();
    final byte[] bytes = new byte[16];

    random.nextBytes(bytes);

    return ByteString.copyFrom(bytes);
  }
}
