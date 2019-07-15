/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.s3;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

public class PolicySigner {

  private final String awsAccessSecret;
  private final String region;

  public PolicySigner(String awsAccessSecret, String region) {
    this.awsAccessSecret = awsAccessSecret;
    this.region          = region;
  }

  public String getSignature(ZonedDateTime now, String policy) {
    try {
      Mac mac = Mac.getInstance("HmacSHA256");

      mac.init(new SecretKeySpec(("AWS4" + awsAccessSecret).getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
      byte[] dateKey = mac.doFinal(now.format(DateTimeFormatter.ofPattern("yyyyMMdd")).getBytes(StandardCharsets.UTF_8));

      mac.init(new SecretKeySpec(dateKey, "HmacSHA256"));
      byte[] dateRegionKey = mac.doFinal(region.getBytes(StandardCharsets.UTF_8));

      mac.init(new SecretKeySpec(dateRegionKey, "HmacSHA256"));
      byte[] dateRegionServiceKey = mac.doFinal("s3".getBytes(StandardCharsets.UTF_8));

      mac.init(new SecretKeySpec(dateRegionServiceKey, "HmacSHA256"));
      byte[] signingKey  = mac.doFinal("aws4_request".getBytes(StandardCharsets.UTF_8));

      mac.init(new SecretKeySpec(signingKey, "HmacSHA256"));

      return Base16Lower.encode(mac.doFinal(policy.getBytes(StandardCharsets.UTF_8)));
    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      throw new AssertionError(e);
    }
  }

}
