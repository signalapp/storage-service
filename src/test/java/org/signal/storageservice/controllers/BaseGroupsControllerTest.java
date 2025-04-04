/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.controllers;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.protobuf.ByteString;
import io.dropwizard.auth.AuthValueFactoryProvider;
import io.dropwizard.testing.junit5.DropwizardExtensionsSupport;
import io.dropwizard.testing.junit5.ResourceExtension;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.NotarySignature;
import org.signal.libsignal.zkgroup.VerificationFailedException;
import org.signal.libsignal.zkgroup.auth.ClientZkAuthOperations;
import org.signal.libsignal.zkgroup.groups.GroupPublicParams;
import org.signal.libsignal.zkgroup.groups.GroupSecretParams;
import org.signal.libsignal.zkgroup.profiles.ClientZkProfileOperations;
import org.signal.libsignal.zkgroup.profiles.ProfileKeyCredentialPresentation;
import org.signal.storageservice.auth.ExternalGroupCredentialGenerator;
import org.signal.storageservice.auth.GroupUser;
import org.signal.storageservice.configuration.GroupConfiguration;
import org.signal.storageservice.providers.InvalidProtocolBufferExceptionMapper;
import org.signal.storageservice.providers.ProtocolBufferMessageBodyProvider;
import org.signal.storageservice.providers.ProtocolBufferValidationErrorMessageBodyWriter;
import org.signal.storageservice.s3.PolicySigner;
import org.signal.storageservice.s3.PostPolicyGenerator;
import org.signal.storageservice.storage.GroupsManager;
import org.signal.storageservice.storage.protos.groups.AccessControl;
import org.signal.storageservice.storage.protos.groups.Group;
import org.signal.storageservice.storage.protos.groups.GroupChange;
import org.signal.storageservice.storage.protos.groups.Member;
import org.signal.storageservice.util.AuthHelper;
import org.signal.storageservice.util.SystemMapper;
import org.signal.storageservice.util.Util;
import org.signal.storageservice.util.TestClock;

@ExtendWith(DropwizardExtensionsSupport.class)
abstract class BaseGroupsControllerTest {
  protected final ExternalGroupCredentialGenerator groupCredentialGenerator = new ExternalGroupCredentialGenerator(Util.generateSecretBytes(32), Clock.systemUTC());
  protected final GroupSecretParams groupSecretParams = GroupSecretParams.generate();
  protected final GroupPublicParams groupPublicParams = groupSecretParams.getPublicParams();
  protected final ProfileKeyCredentialPresentation validUserPresentation = new ClientZkProfileOperations(AuthHelper.GROUPS_SERVER_KEY.getPublicParams()).createProfileKeyCredentialPresentation(groupSecretParams, AuthHelper.VALID_USER_PROFILE_CREDENTIAL);
  protected final ProfileKeyCredentialPresentation validUserTwoPresentation = new ClientZkProfileOperations(AuthHelper.GROUPS_SERVER_KEY.getPublicParams()).createProfileKeyCredentialPresentation(groupSecretParams, AuthHelper.VALID_USER_TWO_PROFILE_CREDENTIAL);
  protected final ProfileKeyCredentialPresentation validUserThreePresentation = new ClientZkProfileOperations(AuthHelper.GROUPS_SERVER_KEY.getPublicParams()).createProfileKeyCredentialPresentation(groupSecretParams, AuthHelper.VALID_USER_THREE_PROFILE_CREDENTIAL);
  protected final ProfileKeyCredentialPresentation validUserFourPresentation = new ClientZkProfileOperations(AuthHelper.GROUPS_SERVER_KEY.getPublicParams()).createProfileKeyCredentialPresentation(groupSecretParams, AuthHelper.VALID_USER_FOUR_PROFILE_CREDENTIAL);
  protected final ByteString validUserId = ByteString.copyFrom(validUserPresentation.getUuidCiphertext().serialize());
  protected final ByteString validUserPniId = ByteString.copyFrom(new ClientZkAuthOperations(AuthHelper.GROUPS_SERVER_KEY.getPublicParams()).createAuthCredentialPresentation(groupSecretParams, AuthHelper.VALID_USER_AUTH_CREDENTIAL).getPniCiphertext().serialize());
  protected final ByteString validUserTwoId = ByteString.copyFrom(validUserTwoPresentation.getUuidCiphertext().serialize());
  protected final ByteString validUserTwoPniId = ByteString.copyFrom(new ClientZkAuthOperations(AuthHelper.GROUPS_SERVER_KEY.getPublicParams()).createAuthCredentialPresentation(groupSecretParams, AuthHelper.VALID_USER_TWO_AUTH_CREDENTIAL).getPniCiphertext().serialize());
  protected final ByteString validUserThreeId = ByteString.copyFrom(validUserThreePresentation.getUuidCiphertext().serialize());
  protected final ByteString validUserThreePniId = ByteString.copyFrom(new ClientZkAuthOperations(AuthHelper.GROUPS_SERVER_KEY.getPublicParams()).createAuthCredentialPresentation(groupSecretParams, AuthHelper.VALID_USER_THREE_AUTH_CREDENTIAL).getPniCiphertext().serialize());
  protected final ByteString validUserFourId = ByteString.copyFrom(validUserFourPresentation.getUuidCiphertext().serialize());
  protected final ByteString validUserFourPniId = ByteString.copyFrom(new ClientZkAuthOperations(AuthHelper.GROUPS_SERVER_KEY.getPublicParams()).createAuthCredentialPresentation(groupSecretParams, AuthHelper.VALID_USER_FOUR_AUTH_CREDENTIAL).getPniCiphertext().serialize());
  protected final GroupsManager groupsManager = mock(GroupsManager.class);
  protected final TestClock clock = TestClock.pinned(Instant.now());
  protected final PostPolicyGenerator postPolicyGenerator = new PostPolicyGenerator("us-west-1", "profile-bucket", "accessKey");
  protected final PolicySigner policySigner = new PolicySigner("accessSecret", "us-west-1");
  protected final Group group = Group.newBuilder()
      .setPublicKey(ByteString.copyFrom(groupPublicParams.serialize()))
      .setAccessControl(AccessControl.newBuilder()
          .setMembers(AccessControl.AccessRequired.MEMBER)
          .setAttributes(AccessControl.AccessRequired.MEMBER))
      .setTitle(ByteString.copyFromUtf8("Some title"))
      .setAvatar(avatarFor(groupPublicParams.getGroupIdentifier().serialize()))
      .setVersion(0)
      .addMembers(Member.newBuilder()
          .setUserId(validUserId)
          .setProfileKey(ByteString.copyFrom(validUserPresentation.getProfileKeyCiphertext().serialize()))
          .setRole(Member.Role.ADMINISTRATOR)
          .setJoinedAtVersion(0)
          .build())
      .addMembers(Member.newBuilder()
          .setUserId(validUserTwoId)
          .setProfileKey(ByteString.copyFrom(validUserTwoPresentation.getProfileKeyCiphertext().serialize()))
          .setRole(Member.Role.DEFAULT)
          .setJoinedAtVersion(0)
          .build())
      .build();


  protected final ResourceExtension resources = ResourceExtension.builder()
                                                                 .addProvider(AuthHelper.getAuthFilter())
                                                                 .addProvider(new AuthValueFactoryProvider.Binder<>(GroupUser.class))
                                                                 .addProvider(new ProtocolBufferMessageBodyProvider())
                                                                 .addProvider(new ProtocolBufferValidationErrorMessageBodyWriter())
                                                                 .addProvider(new InvalidProtocolBufferExceptionMapper())
                                                                 .setMapper(SystemMapper.getMapper())
                                                                 .addResource(new GroupsV1Controller(clock, groupsManager, AuthHelper.GROUPS_SERVER_KEY, policySigner, postPolicyGenerator, getGroupConfiguration(), groupCredentialGenerator))
                                                                 .addResource(new GroupsController(clock, groupsManager, AuthHelper.GROUPS_SERVER_KEY, policySigner, postPolicyGenerator, getGroupConfiguration(), groupCredentialGenerator))
                                                                 .build();

  protected GroupConfiguration getGroupConfiguration() {
    return new GroupConfiguration(42, 1024, 8192, new byte[32], null, null);
  }

  protected String avatarFor(byte[] groupId) {
    byte[] object = new byte[16];
    new SecureRandom().nextBytes(object);

    return "groups/"
        + Base64.getUrlEncoder().withoutPadding().encodeToString(groupId)
        + "/"
        + Base64.getUrlEncoder().withoutPadding().encodeToString(object);
  }

  @BeforeEach
  void resetGroupsManager() {
    reset(groupsManager);
  }

  protected void setupGroupsManagerBehaviors(Group group) {
    when(groupsManager.getGroup(eq(ByteString.copyFrom(groupPublicParams.getGroupIdentifier().serialize()))))
        .thenReturn(CompletableFuture.completedFuture(Optional.of(group)));

    setupGroupsManagerForWrites();
  }

  protected void setupGroupsManagerForWrites() {
    when(groupsManager.updateGroup(eq(ByteString.copyFrom(groupPublicParams.getGroupIdentifier().serialize())), any(Group.class)))
        .thenReturn(CompletableFuture.completedFuture(Optional.empty()));

    when(groupsManager.appendChangeRecord(eq(ByteString.copyFrom(groupPublicParams.getGroupIdentifier().serialize())), eq(1), any(GroupChange.class), any(Group.class)))
        .thenReturn(CompletableFuture.completedFuture(true));
  }

  protected void verifyNoGroupWrites() {
    verify(groupsManager, never()).appendChangeRecord(any(), anyInt(), any(), any());
    verify(groupsManager, never()).createGroup(any(), any());
    verify(groupsManager, never()).updateGroup(any(), any());
  }

  protected void setMockGroupState(Group.Builder groupBuilder) {
    when(groupsManager.getGroup(eq(ByteString.copyFrom(groupPublicParams.getGroupIdentifier().serialize()))))
        .thenReturn(CompletableFuture.completedFuture(Optional.of(groupBuilder.build())));
  }

  protected void verifyGroupModification(Group.Builder groupBuilder, GroupChange.Actions.Builder groupChangeActionsBuilder, int expectedChangeEpoch, Response response, ByteString modificationUserId)
      throws IOException, InvalidInputException, VerificationFailedException {
    final Group newGroupState = groupBuilder.build();
    final ByteString groupId = ByteString.copyFrom(groupPublicParams.getGroupIdentifier().serialize());
    final GroupChange.Actions actions = groupChangeActionsBuilder.build();

    ArgumentCaptor<GroupChange> groupChangeCaptor = ArgumentCaptor.forClass(GroupChange.class);

    verify(groupsManager).updateGroup(eq(groupId), eq(newGroupState));
    verify(groupsManager).appendChangeRecord(
        eq(groupId),
        eq(newGroupState.getVersion()),
        groupChangeCaptor.capture(),
        eq(newGroupState));
    GroupChange capturedGroupChange = groupChangeCaptor.getValue();
    AuthHelper.GROUPS_SERVER_KEY.getPublicParams().verifySignature(capturedGroupChange.getActions().toByteArray(), new NotarySignature(capturedGroupChange.getServerSignature().toByteArray()));
    GroupChange.Actions capturedActions = GroupChange.Actions.parseFrom(capturedGroupChange.getActions());
    assertThat(capturedActions).isEqualTo(actions.toBuilder().setSourceUuid(modificationUserId).build());
    assertThat(capturedGroupChange.getChangeEpoch()).isEqualTo(expectedChangeEpoch);

    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.hasEntity()).isTrue();
    assertThat(response.getMediaType().toString()).isEqualTo("application/x-protobuf");
    final GroupChange signedChange = GroupChange.parseFrom(response.readEntity(InputStream.class));
    final GroupChange.Actions signedActions = GroupChange.Actions.parseFrom(signedChange.getActions());
    assertThat(signedActions.toBuilder().clearSourceUuid().build()).isEqualTo(actions);
    assertThat(signedActions.getSourceUuid()).isEqualTo(modificationUserId);
    assertThat(signedChange.getChangeEpoch()).isEqualTo(expectedChangeEpoch);
    assertThat(signedChange.getServerSignature()).isEqualTo(capturedGroupChange.getServerSignature());
  }
}
