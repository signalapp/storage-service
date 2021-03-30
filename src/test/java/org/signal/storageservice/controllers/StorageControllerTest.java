/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.controllers;

import com.google.protobuf.ByteString;
import io.dropwizard.auth.AuthValueFactoryProvider;
import io.dropwizard.testing.junit.ResourceTestRule;
import org.glassfish.jersey.client.ClientProperties;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.signal.storageservice.auth.User;
import org.signal.storageservice.providers.InvalidProtocolBufferExceptionMapper;
import org.signal.storageservice.providers.ProtocolBufferMediaType;
import org.signal.storageservice.providers.ProtocolBufferMessageBodyProvider;
import org.signal.storageservice.storage.StorageManager;
import org.signal.storageservice.storage.protos.contacts.ReadOperation;
import org.signal.storageservice.storage.protos.contacts.StorageItem;
import org.signal.storageservice.storage.protos.contacts.StorageItems;
import org.signal.storageservice.storage.protos.contacts.StorageManifest;
import org.signal.storageservice.storage.protos.contacts.WriteOperation;
import org.signal.storageservice.util.AuthHelper;
import org.signal.storageservice.util.SystemMapper;

import javax.ws.rs.client.Entity;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyList;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

public class StorageControllerTest {

  private final StorageManager storageManager = mock(StorageManager.class);

  @Rule
  public final ResourceTestRule resources = ResourceTestRule.builder()
                                                            .addProvider(AuthHelper.getAuthFilter())
                                                            .addProvider(new AuthValueFactoryProvider.Binder<>(User.class))
                                                            .addProvider(new ProtocolBufferMessageBodyProvider())
                                                            .addProvider(new InvalidProtocolBufferExceptionMapper())
                                                            .setMapper(SystemMapper.getMapper())
                                                            .addResource(new StorageController(storageManager))
                                                            .setClientConfigurator(clientConfig -> clientConfig.property(ClientProperties.SUPPRESS_HTTP_COMPLIANCE_VALIDATION, true))
                                                            .build();

  @Test
  public void testGetManifest() throws IOException {
    when(storageManager.getManifest(eq(new User(UUID.fromString(AuthHelper.VALID_USER)))))
        .thenReturn(CompletableFuture.completedFuture(Optional.of(StorageManifest.newBuilder()
                                                                                 .setVersion(22)
                                                                                 .setValue(ByteString.copyFromUtf8("A manifest"))
                                                                                 .build())));

    Response response = resources.getJerseyTest()
                                 .target("/v1/storage/manifest")
                                 .request()
                                 .header("Authorization", AuthHelper.getAuthHeader(AuthHelper.VALID_USER, AuthHelper.VALID_PASSWORD))
                                 .get();

    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.hasEntity()).isTrue();
    assertThat(response.getMediaType().toString()).isEqualTo("application/x-protobuf");

    byte[] entity = response.readEntity(InputStream.class).readAllBytes();

    StorageManifest manifest = StorageManifest.parseFrom(entity);
    assertThat(manifest.getVersion()).isEqualTo(22);
    assertThat(manifest.getValue().toStringUtf8()).isEqualTo("A manifest");

    verify(storageManager, times(1)).getManifest(eq(new User(UUID.fromString(AuthHelper.VALID_USER))));
    verifyNoMoreInteractions(storageManager);
  }

  @Test
  public void testGetManifestIfDifferentFromVersionSuccess() throws IOException {
    when(storageManager.getManifestIfNotVersion(eq(new User(UUID.fromString(AuthHelper.VALID_USER))), eq(21L)))
        .thenReturn(CompletableFuture.completedFuture(Optional.of(StorageManifest.newBuilder()
                                                                                 .setVersion(22)
                                                                                 .setValue(ByteString.copyFromUtf8("A manifest"))
                                                                                 .build())));

    Response response = resources.getJerseyTest()
                                 .target("/v1/storage/manifest/version/21")
                                 .request()
                                 .header("Authorization", AuthHelper.getAuthHeader(AuthHelper.VALID_USER, AuthHelper.VALID_PASSWORD))
                                 .get();

    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.hasEntity()).isTrue();
    assertThat(response.getMediaType().toString()).isEqualTo("application/x-protobuf");

    byte[] entity = response.readEntity(InputStream.class).readAllBytes();

    StorageManifest manifest = StorageManifest.parseFrom(entity);
    assertThat(manifest.getVersion()).isEqualTo(22L);
    assertThat(manifest.getValue().toStringUtf8()).isEqualTo("A manifest");

    verify(storageManager, times(1)).getManifestIfNotVersion(eq(new User(UUID.fromString(AuthHelper.VALID_USER))), eq(21L));
    verifyNoMoreInteractions(storageManager);
  }

  @Test
  public void testGetManifestIfDifferentFromVersionNoUpdate() throws IOException {
    when(storageManager.getManifestIfNotVersion(eq(new User(UUID.fromString(AuthHelper.VALID_USER))), eq(22L)))
        .thenReturn(CompletableFuture.completedFuture(Optional.empty()));

    Response response = resources.getJerseyTest()
                                 .target("/v1/storage/manifest/version/22")
                                 .request()
                                 .header("Authorization", AuthHelper.getAuthHeader(AuthHelper.VALID_USER, AuthHelper.VALID_PASSWORD))
                                 .get();

    assertThat(response.getStatus()).isEqualTo(204);

    verify(storageManager, times(1)).getManifestIfNotVersion(eq(new User(UUID.fromString(AuthHelper.VALID_USER))), eq(22L));
    verifyNoMoreInteractions(storageManager);
  }


  @Test
  public void testGetManifestUnauthorized() throws IOException {
    when(storageManager.getManifest(eq(new User(UUID.fromString(AuthHelper.VALID_USER)))))
        .thenReturn(CompletableFuture.completedFuture(Optional.of(StorageManifest.newBuilder()
                                                                                 .setVersion(22)
                                                                                 .setValue(ByteString.copyFromUtf8("A manifest"))
                                                                                 .build())));

    Response response = resources.getJerseyTest()
                                 .target("/v1/storage/manifest")
                                 .request()
                                 .header("Authorization", AuthHelper.getAuthHeader(AuthHelper.INVALID_USER, AuthHelper.INVALID_PASSWORD))
                                 .get();

    assertThat(response.getStatus()).isEqualTo(401);
    verifyNoMoreInteractions(storageManager);
  }

  @Test
  public void testGetManifestFiveHundred() throws IOException {
    when(storageManager.getManifest(eq(new User(UUID.fromString(AuthHelper.VALID_USER)))))
        .thenReturn(CompletableFuture.failedFuture(new RuntimeException("Bad news")));

    Response response = resources.getJerseyTest()
                                 .target("/v1/storage/manifest")
                                 .request()
                                 .header("Authorization", AuthHelper.getAuthHeader(AuthHelper.VALID_USER, AuthHelper.VALID_PASSWORD))
                                 .get();

    assertThat(response.getStatus()).isEqualTo(500);

    verify(storageManager).getManifest(eq(new User(UUID.fromString(AuthHelper.VALID_USER))));
    verifyNoMoreInteractions(storageManager);
  }

  @Test
  public void testGetManifestNotFound() throws IOException {
    when(storageManager.getManifest(eq(new User(UUID.fromString(AuthHelper.VALID_USER))))).thenReturn(CompletableFuture.completedFuture(Optional.empty()));

    Response response = resources.getJerseyTest()
                                 .target("/v1/storage/manifest")
                                 .request()
                                 .header("Authorization", AuthHelper.getAuthHeader(AuthHelper.VALID_USER, AuthHelper.VALID_PASSWORD))
                                 .get();

    assertThat(response.getStatus()).isEqualTo(404);
    verify(storageManager, times(1)).getManifest(eq(new User(UUID.fromString(AuthHelper.VALID_USER))));
    verifyNoMoreInteractions(storageManager);
  }

  @Test
  public void testWrite() {
    when(storageManager.set(eq(new User(UUID.fromString(AuthHelper.VALID_USER))), any(StorageManifest.class), anyList(), anyList())).thenReturn(CompletableFuture.completedFuture(Optional.empty()));

    StorageManifest manifest = StorageManifest.newBuilder()
                                              .setVersion(1337)
                                              .setValue(ByteString.copyFromUtf8("A manifest"))
                                              .build();

    StorageItem insertOne = StorageItem.newBuilder()
                                       .setKey(ByteString.copyFromUtf8("keyOne"))
                                       .setValue(ByteString.copyFromUtf8("valueOne"))
                                       .build();

    StorageItem insertTwo = StorageItem.newBuilder()
                                       .setKey(ByteString.copyFromUtf8("keyTwo"))
                                       .setValue(ByteString.copyFromUtf8("valueTwo"))
                                       .build();

    ByteString deleteOne   = ByteString.copyFromUtf8("deleteKeyOne"  );
    ByteString deleteTwo   = ByteString.copyFromUtf8("deleteKeyTwo"  );
    ByteString deleteThree = ByteString.copyFromUtf8("deleteKeyThree");


    WriteOperation writeOperation = WriteOperation.newBuilder()
                                                  .setManifest(manifest)
                                                  .addInsertItem(insertOne)
                                                  .addInsertItem(insertTwo)
                                                  .addDeleteKey(deleteOne)
                                                  .addDeleteKey(deleteTwo)
                                                  .addDeleteKey(deleteThree)
                                                  .build();

    Response response = resources.getJerseyTest()
                                 .target("/v1/storage/")
                                 .request()
                                 .header("Authorization", AuthHelper.getAuthHeader(AuthHelper.VALID_USER, AuthHelper.VALID_PASSWORD))
                                 .put(Entity.entity(writeOperation.toByteArray(), ProtocolBufferMediaType.APPLICATION_PROTOBUF));

    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.hasEntity()).isFalse();

    ArgumentCaptor<List<StorageItem>> insertCaptor = ArgumentCaptor.forClass(List.class);
    ArgumentCaptor<List<ByteString>>  deleteCaptor = ArgumentCaptor.forClass(List.class);

    verify(storageManager, times(1)).set(eq(new User(UUID.fromString(AuthHelper.VALID_USER))), eq(manifest), insertCaptor.capture(), deleteCaptor.capture());
    verifyNoMoreInteractions(storageManager);

    assertThat(insertCaptor.getValue().size()).isEqualTo(2);
    assertThat(insertCaptor.getValue().get(0)).isEqualTo(insertOne);
    assertThat(insertCaptor.getValue().get(1)).isEqualTo(insertTwo);

    assertThat(deleteCaptor.getValue().size()).isEqualTo(3);
    assertThat(deleteCaptor.getValue().get(0)).isEqualTo(deleteOne);
    assertThat(deleteCaptor.getValue().get(1)).isEqualTo(deleteTwo);
    assertThat(deleteCaptor.getValue().get(2)).isEqualTo(deleteThree);
  }

  @Test
  public void testWriteUnauthorized() {
    when(storageManager.set(eq(new User(UUID.fromString(AuthHelper.VALID_USER))), any(StorageManifest.class), anyList(), anyList())).thenReturn(CompletableFuture.completedFuture(Optional.empty()));

    StorageManifest manifest = StorageManifest.newBuilder()
                                              .setVersion(1337)
                                              .setValue(ByteString.copyFromUtf8("A manifest"))
                                              .build();

    StorageItem insertOne = StorageItem.newBuilder()
                                       .setKey(ByteString.copyFromUtf8("keyOne"))
                                       .setValue(ByteString.copyFromUtf8("valueOne"))
                                       .build();

    StorageItem insertTwo = StorageItem.newBuilder()
                                       .setKey(ByteString.copyFromUtf8("keyTwo"))
                                       .setValue(ByteString.copyFromUtf8("valueTwo"))
                                       .build();

    ByteString deleteOne   = ByteString.copyFromUtf8("deleteKeyOne"  );
    ByteString deleteTwo   = ByteString.copyFromUtf8("deleteKeyTwo"  );
    ByteString deleteThree = ByteString.copyFromUtf8("deleteKeyThree");


    WriteOperation writeOperation = WriteOperation.newBuilder()
                                                  .setManifest(manifest)
                                                  .addInsertItem(insertOne)
                                                  .addInsertItem(insertTwo)
                                                  .addDeleteKey(deleteOne)
                                                  .addDeleteKey(deleteTwo)
                                                  .addDeleteKey(deleteThree)
                                                  .build();

    Response response = resources.getJerseyTest()
                                 .target("/v1/storage/")
                                 .request()
                                 .header("Authorization", AuthHelper.getAuthHeader(AuthHelper.INVALID_USER, AuthHelper.INVALID_PASSWORD))
                                 .put(Entity.entity(writeOperation.toByteArray(), ProtocolBufferMediaType.APPLICATION_PROTOBUF));

    assertThat(response.getStatus()).isEqualTo(401);

    verifyNoMoreInteractions(storageManager);
  }

  @Test
  public void testWriteStale() throws IOException {
    StorageManifest currentManifest = StorageManifest.newBuilder()
                                                     .setVersion(1000)
                                                     .setValue(ByteString.copyFromUtf8("Current manifest"))
                                                     .build();

    when(storageManager.set(eq(new User(UUID.fromString(AuthHelper.VALID_USER))), any(StorageManifest.class), anyList(), anyList()))
        .thenReturn(CompletableFuture.completedFuture(Optional.of(currentManifest)));

    StorageManifest stale = StorageManifest.newBuilder()
                                           .setVersion(1000)
                                           .setValue(ByteString.copyFromUtf8("Some manifest"))
                                           .build();

    StorageItem insertOne = StorageItem.newBuilder()
                                       .setKey(ByteString.copyFromUtf8("keyOne"))
                                       .setValue(ByteString.copyFromUtf8("valueOne"))
                                       .build();

    StorageItem insertTwo = StorageItem.newBuilder()
                                       .setKey(ByteString.copyFromUtf8("keyTwo"))
                                       .setValue(ByteString.copyFromUtf8("valueTwo"))
                                       .build();

    ByteString deleteOne   = ByteString.copyFromUtf8("deleteKeyOne"  );
    ByteString deleteTwo   = ByteString.copyFromUtf8("deleteKeyTwo"  );
    ByteString deleteThree = ByteString.copyFromUtf8("deleteKeyThree");


    WriteOperation writeOperation = WriteOperation.newBuilder()
                                                  .setManifest(stale)
                                                  .addInsertItem(insertOne)
                                                  .addInsertItem(insertTwo)
                                                  .addDeleteKey(deleteOne)
                                                  .addDeleteKey(deleteTwo)
                                                  .addDeleteKey(deleteThree)
                                                  .build();

    Response response = resources.getJerseyTest()
                                 .target("/v1/storage/")
                                 .request()
                                 .header("Authorization", AuthHelper.getAuthHeader(AuthHelper.VALID_USER, AuthHelper.VALID_PASSWORD))
                                 .put(Entity.entity(writeOperation.toByteArray(), ProtocolBufferMediaType.APPLICATION_PROTOBUF));

    assertThat(response.getStatus()).isEqualTo(409);
    assertThat(response.hasEntity()).isTrue();
    assertThat(response.getMediaType().toString()).isEqualTo(ProtocolBufferMediaType.APPLICATION_PROTOBUF);


    byte[]          entity   = response.readEntity(InputStream.class).readAllBytes();
    StorageManifest manifest = StorageManifest.parseFrom(entity);

    assertThat(manifest).isEqualTo(currentManifest);

    verify(storageManager, times(1)).set(eq(new User(UUID.fromString(AuthHelper.VALID_USER))), eq(stale), anyList(), anyList());
    verifyNoMoreInteractions(storageManager);
  }

  @Test
  public void testReadEmpty() {
    Response response = resources.getJerseyTest()
                                 .target("/v1/storage/read")
                                 .request()
                                 .header("Authorization", AuthHelper.getAuthHeader(AuthHelper.VALID_USER, AuthHelper.VALID_PASSWORD))
                                 .put(Entity.entity(ReadOperation.newBuilder().build().toByteArray(), ProtocolBufferMediaType.APPLICATION_PROTOBUF));

    assertThat(response.getStatus()).isEqualTo(400);
  }

  @Test
  public void testRead() throws IOException {
    StorageItem queryOne = StorageItem.newBuilder()
                                      .setKey(ByteString.copyFromUtf8("keyOne"))
                                      .setValue(ByteString.copyFromUtf8("valueOne"))
                                      .build();

    StorageItem queryTwo = StorageItem.newBuilder()
                                      .setKey(ByteString.copyFromUtf8("keyTwo"))
                                      .setValue(ByteString.copyFromUtf8("valueTwo"))
                                      .build();

    when(storageManager.getItems(eq(new User(UUID.fromString(AuthHelper.VALID_USER))), anyList()))
        .thenReturn(CompletableFuture.completedFuture(List.of(queryOne, queryTwo)));


    ReadOperation readOperation = ReadOperation.newBuilder()
                                               .addReadKey(queryOne.getKey())
                                               .addReadKey(queryTwo.getKey())
                                               .build();

    Response response = resources.getJerseyTest()
                                 .target("/v1/storage/read")
                                 .request()
                                 .header("Authorization", AuthHelper.getAuthHeader(AuthHelper.VALID_USER, AuthHelper.VALID_PASSWORD))
                                 .put(Entity.entity(readOperation.toByteArray(), ProtocolBufferMediaType.APPLICATION_PROTOBUF));

    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.hasEntity()).isTrue();

    byte[] entity = response.readEntity(InputStream.class).readAllBytes();

    StorageItems contacts = StorageItems.parseFrom(entity);
    assertThat(contacts.getContactsList().size()).isEqualTo(2);
    assertThat(contacts.getContactsList().contains(queryOne)).isTrue();
    assertThat(contacts.getContactsList().contains(queryTwo)).isTrue();

    ArgumentCaptor<List<ByteString>> keysCaptor = ArgumentCaptor.forClass(List.class);

    verify(storageManager, times(1)).getItems(eq(new User(UUID.fromString(AuthHelper.VALID_USER))), keysCaptor.capture());
    verifyNoMoreInteractions(storageManager);

    assertThat(keysCaptor.getValue().size()).isEqualTo(2);
    assertThat(keysCaptor.getValue().contains(queryOne.getKey())).isTrue();
    assertThat(keysCaptor.getValue().contains(queryTwo.getKey())).isTrue();
  }

  @Test
  public void testDelete() {
    when(storageManager.delete(any())).thenReturn(CompletableFuture.completedFuture(null));

    Response response = resources.getJerseyTest()
            .target("/v1/storage")
            .request()
            .header("Authorization", AuthHelper.getAuthHeader(AuthHelper.VALID_USER, AuthHelper.VALID_PASSWORD))
            .delete();

    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.hasEntity()).isFalse();

    verify(storageManager).delete(eq(new User(UUID.fromString(AuthHelper.VALID_USER))));
    verifyNoMoreInteractions(storageManager);
  }

  @Test
  public void testDeleteUnauthorized() {
    when(storageManager.clearItems(any())).thenReturn(CompletableFuture.completedFuture(null));

    Response response = resources.getJerseyTest()
            .target("/v1/storage")
            .request()
            .header("Authorization", AuthHelper.getAuthHeader(AuthHelper.INVALID_USER, AuthHelper.INVALID_PASSWORD))
            .delete();

    assertThat(response.getStatus()).isEqualTo(401);

    verify(storageManager, never()).clearItems(any());
  }
}
