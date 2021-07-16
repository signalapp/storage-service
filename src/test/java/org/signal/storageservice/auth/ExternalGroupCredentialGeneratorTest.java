/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.google.protobuf.ByteString;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.util.stream.Stream;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.signal.storageservice.util.Util;

public class ExternalGroupCredentialGeneratorTest {

  @SuppressWarnings("unused")
  static Stream<Arguments> testArgumentsProvider() {
    return Stream.of(
        arguments(true, "1"),
        arguments(false, "0")
    );
  }

  @ParameterizedTest
  @MethodSource("testArgumentsProvider")
  public void testGenerateValidCredentials(boolean isAllowedToCreateGroupCalls, String part4)
      throws DecoderException, NoSuchAlgorithmException, InvalidKeyException {
    Clock clock = mock(Clock.class);
    final long timeInMillis = new SecureRandom().nextLong() & Long.MAX_VALUE;
    when(clock.millis()).thenReturn(timeInMillis);

    byte[] key = Util.generateSecretBytes(32);
    ExternalGroupCredentialGenerator generator = new ExternalGroupCredentialGenerator(key, clock);
    ByteString uuid = ByteString.copyFrom(Util.generateSecretBytes(16));
    ByteString groupId = ByteString.copyFrom(Util.generateSecretBytes(16));

    String token = generator.generateFor(uuid, groupId, isAllowedToCreateGroupCalls);

    String[] parts = token.split(":");
    assertThat(parts.length).isEqualTo(6);

    assertThat(parts[0]).isEqualTo("2");
    assertArrayEquals(Hex.decodeHex(parts[1]), MessageDigest.getInstance("SHA-256").digest(uuid.toByteArray()));
    assertArrayEquals(Hex.decodeHex(parts[2]), groupId.toByteArray());
    assertThat(Long.parseLong(parts[3])).isEqualTo(timeInMillis / 1000);
    assertThat(parts[4]).isEqualTo(part4);

    byte[] theirMac = Hex.decodeHex(parts[5]);
    Mac hmac = Mac.getInstance("HmacSHA256");
    hmac.init(new SecretKeySpec(key, "HmacSHA256"));
    byte[] ourMac = Util.truncate(hmac.doFinal(
        ("2:" + parts[1] + ":" + parts[2] + ":" + parts[3] + ":" + part4).getBytes(StandardCharsets.UTF_8)), 10);
    assertArrayEquals(ourMac, theirMac);
  }
}
