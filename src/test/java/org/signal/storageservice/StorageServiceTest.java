/*
 * Copyright 2026 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;

import com.google.protobuf.ByteString;
import io.dropwizard.testing.junit5.DropwizardAppExtension;
import io.dropwizard.testing.junit5.DropwizardExtensionsSupport;
import io.dropwizard.util.Resources;
import jakarta.ws.rs.client.Entity;
import jakarta.ws.rs.client.Invocation;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.signal.storageservice.providers.ProtocolBufferMediaType;
import org.signal.storageservice.storage.protos.contacts.StorageManifest;
import org.signal.storageservice.storage.protos.contacts.WriteOperation;

@ExtendWith(DropwizardExtensionsSupport.class)
class StorageServiceTest {

  private static final DropwizardAppExtension<StorageServiceConfiguration> EXTENSION = new DropwizardAppExtension<>(
      StorageService.class, Resources.getResource("config/test.yml").getPath());

  @Test
  void start() {
    // make sure the service nominally starts and responds to health and readiness checks
    try (final Response ping = EXTENSION.client()
        .target("http://localhost:%d/ping".formatted(EXTENSION.getAdminPort()))
        .request()
        .get()) {

      assertEquals(200, ping.getStatus());
    }

    try (final Response healthCheck = EXTENSION.client()
        .target("http://localhost:%d/ping".formatted(EXTENSION.getLocalPort()))
        .request()
        .get()) {

      assertEquals(200, healthCheck.getStatus());
    }

    // the first call runs warm-up queries against every configured table
    try (final Response ready = EXTENSION.client()
        .target("http://localhost:%d/_ready".formatted(EXTENSION.getLocalPort()))
        .request()
        .get()) {

      assertEquals(200, ready.getStatus());
    }
  }

  @Test
  void storageManifest() throws Exception {
    // confirm that the local Bigtable emulator nominally works
    final UUID user = UUID.randomUUID();

    try (final Response response = authenticatedRequest(user, "/v1/storage/manifest").get()) {
      assertEquals(404, response.getStatus());
    }

    final StorageManifest manifest = StorageManifest.newBuilder()
        .setVersion(1)
        .setValue(ByteString.copyFromUtf8("manifest"))
        .build();

    try (final Response response = authenticatedRequest(user, "/v1/storage")
        .put(Entity.entity(WriteOperation.newBuilder().setManifest(manifest).build().toByteArray(),
            ProtocolBufferMediaType.APPLICATION_PROTOBUF))) {

      assertEquals(200, response.getStatus());
    }

    try (final Response response = authenticatedRequest(user, "/v1/storage/manifest").get()) {
      assertEquals(200, response.getStatus());
      assertArrayEquals(manifest.toByteArray(), response.readEntity(byte[].class));
    }
  }

  private static Invocation.Builder authenticatedRequest(final UUID user, final String path) throws Exception {
    return EXTENSION.client()
        .target("http://localhost:%d%s".formatted(EXTENSION.getLocalPort(), path))
        .request(ProtocolBufferMediaType.APPLICATION_PROTOBUF)
        .header(HttpHeaders.AUTHORIZATION, basicAuthHeader(user));
  }

  /// Matches credential generation in Signal Server
  private static String basicAuthHeader(final UUID user) throws Exception {
    final String username = user.toString();
    final String prefix = username + ":" + Instant.now().getEpochSecond();

    final Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(EXTENSION.getConfiguration().getAuthenticationConfiguration().getKey(), "HmacSHA256"));
    final byte[] signature = mac.doFinal(prefix.getBytes(StandardCharsets.UTF_8));

    final String password = prefix + ":" + HexFormat.of().formatHex(signature, 0, 10);

    return "Basic " + Base64.getEncoder()
        .encodeToString((username + ":" + password).getBytes(StandardCharsets.UTF_8));
  }
}
