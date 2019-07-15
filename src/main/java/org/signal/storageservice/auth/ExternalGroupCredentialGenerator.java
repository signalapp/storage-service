/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.auth;

import com.google.protobuf.ByteString;
import org.apache.commons.codec.binary.Hex;
import org.signal.storageservice.util.Util;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class ExternalGroupCredentialGenerator {

  private final Logger logger = LoggerFactory.getLogger(ExternalGroupCredentialGenerator.class);

  private final byte[]  key;

  public ExternalGroupCredentialGenerator(byte[] key) {
    this.key = key;
  }

  public String generateFor(ByteString uuidCiphertext, ByteString groupId) {
    Mac           mac                = getMacInstance();
    MessageDigest digest             = getDigestInstance();
    long          currentTimeSeconds = System.currentTimeMillis() / 1000;
    String        prefix             = Hex.encodeHexString(digest.digest(uuidCiphertext.toByteArray())) + ":"  + Hex.encodeHexString(groupId.toByteArray()) + ":" + currentTimeSeconds;
    String        output             = Hex.encodeHexString(Util.truncate(getHmac(key, prefix.getBytes(), mac), 10));

    return prefix + ":" + output;
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

  private byte[] getHmac(byte[] key, byte[] input, Mac mac) {
    try {
      mac.init(new SecretKeySpec(key, "HmacSHA256"));
      return mac.doFinal(input);
    } catch (InvalidKeyException e) {
      throw new AssertionError(e);
    }
  }


}
