/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.auth;

import com.google.protobuf.ByteString;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.junit.Test;
import org.signal.storageservice.util.Util;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.Assert.assertArrayEquals;

public class ExternalGroupCredentialGeneratorTest {

  @Test
  public void testGenerateValidCredentials() throws DecoderException, NoSuchAlgorithmException, InvalidKeyException {
    byte[]                           key       = Util.generateSecretBytes(32);
    ExternalGroupCredentialGenerator generator = new ExternalGroupCredentialGenerator(key);
    ByteString                       uuid      = ByteString.copyFrom(Util.generateSecretBytes(16));
    ByteString                       groupId   = ByteString.copyFrom(Util.generateSecretBytes(16));

    String token = generator.generateFor(uuid, groupId);

    String[] parts = token.split(":");
    assertThat(parts.length).isEqualTo(4);

    byte[] theirUuid      = Hex.decodeHex(parts[0]);
    byte[] theirGroupId   = Hex.decodeHex(parts[1]);
    long   theirTimestamp = Long.parseLong(parts[2]);
    byte[] theirMac       = Hex.decodeHex(parts[3]);

    Mac    hmac   = Mac.getInstance("HmacSHA256");
    hmac.init(new SecretKeySpec(key, "HmacSHA256"));
    byte[] ourMac = Util.truncate(hmac.doFinal((parts[0] + ":" + parts[1] + ":" + parts[2]).getBytes()), 10);

    assertArrayEquals(ourMac, theirMac);

    assertArrayEquals(theirUuid, MessageDigest.getInstance("SHA-256").digest(uuid.toByteArray()));
    assertArrayEquals(theirGroupId, groupId.toByteArray());
    assertThat(theirTimestamp).isBetween((System.currentTimeMillis() / 1000) - TimeUnit.MINUTES.toSeconds(1), (System.currentTimeMillis() / 1000) + TimeUnit.SECONDS.toMillis(2));

  }

}
