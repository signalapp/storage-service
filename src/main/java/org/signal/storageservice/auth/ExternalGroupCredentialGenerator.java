/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.auth;

import com.google.protobuf.ByteString;
import org.apache.commons.codec.binary.Hex;
import org.signal.storageservice.util.Util;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;

public class ExternalGroupCredentialGenerator {

  private final byte[] key;
  private final Clock clock;

  public ExternalGroupCredentialGenerator(byte[] key, Clock clock) {
    this.key = key;
    this.clock = clock;
  }

  public String generateFor(ByteString uuidCiphertext, ByteString groupId, boolean isAllowedToInitiateGroupCall) {
    final MessageDigest digest = getDigestInstance();
    final long currentTimeSeconds = clock.millis() / 1000;
    String encodedData =
        "2:"
        + Hex.encodeHexString(digest.digest(uuidCiphertext.toByteArray())) + ":"
        + Hex.encodeHexString(groupId.toByteArray()) + ":"
        + currentTimeSeconds + ":"
        + (isAllowedToInitiateGroupCall ? "1" : "0");
    String truncatedHmac = Hex.encodeHexString(
        Util.truncate(getHmac(key, encodedData.getBytes(StandardCharsets.UTF_8)), 10));

    return encodedData + ":" + truncatedHmac;
  }

  private Mac getMacInstance() {
    try {
      return Mac.getInstance("HmacSHA256");
    } catch (NoSuchAlgorithmException e) {
      throw new AssertionError(e);
    }
  }

  private MessageDigest getDigestInstance() {
    try {
      return MessageDigest.getInstance("SHA-256");
    } catch (NoSuchAlgorithmException e) {
      throw new AssertionError(e);
    }
  }

  private byte[] getHmac(byte[] key, byte[] input) {
    try {
      final Mac mac = getMacInstance();
      mac.init(new SecretKeySpec(key, "HmacSHA256"));
      return mac.doFinal(input);
    } catch (InvalidKeyException e) {
      throw new AssertionError(e);
    }
  }
}
