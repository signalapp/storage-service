/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.controllers;

import com.google.api.client.util.Base64;
import com.google.protobuf.ByteString;
import io.dropwizard.auth.AuthValueFactoryProvider;
import io.dropwizard.testing.junit.ResourceTestRule;
import org.junit.Before;
import org.junit.Rule;
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
import org.signal.storageservice.storage.protos.groups.Member;
import org.signal.storageservice.util.AuthHelper;
import org.signal.storageservice.util.SystemMapper;
import org.signal.storageservice.util.Util;
import org.signal.zkgroup.groups.GroupPublicParams;
import org.signal.zkgroup.groups.GroupSecretParams;
import org.signal.zkgroup.profiles.ClientZkProfileOperations;
import org.signal.zkgroup.profiles.ProfileKeyCredentialPresentation;

import java.security.SecureRandom;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;

public abstract class BaseGroupsControllerTest {
  protected final ExternalGroupCredentialGenerator groupCredentialGenerator   = new ExternalGroupCredentialGenerator(Util.generateSecretBytes(32));
  protected final GroupSecretParams                groupSecretParams          = GroupSecretParams.generate();
  protected final GroupPublicParams                groupPublicParams          = groupSecretParams.getPublicParams();
  protected final ProfileKeyCredentialPresentation validUserPresentation      = new ClientZkProfileOperations(AuthHelper.GROUPS_SERVER_KEY.getPublicParams()).createProfileKeyCredentialPresentation(groupSecretParams, AuthHelper.VALID_USER_PROFILE_CREDENTIAL);
  protected final ProfileKeyCredentialPresentation validUserTwoPresentation   = new ClientZkProfileOperations(AuthHelper.GROUPS_SERVER_KEY.getPublicParams()).createProfileKeyCredentialPresentation(groupSecretParams, AuthHelper.VALID_USER_TWO_PROFILE_CREDENTIAL);
  protected final ProfileKeyCredentialPresentation validUserThreePresentation = new ClientZkProfileOperations(AuthHelper.GROUPS_SERVER_KEY.getPublicParams()).createProfileKeyCredentialPresentation(groupSecretParams, AuthHelper.VALID_USER_THREE_PROFILE_CREDENTIAL);
  protected final GroupsManager                    groupsManager              = mock(GroupsManager.class);
  protected final PostPolicyGenerator              postPolicyGenerator        = new PostPolicyGenerator("us-west-1", "profile-bucket", "accessKey");
  protected final PolicySigner                     policySigner               = new PolicySigner("accessSecret", "us-west-1");
  protected final Group                            group                      = Group.newBuilder()
                                                                                     .setPublicKey(ByteString.copyFrom(groupPublicParams.serialize()))
                                                                                     .setAccessControl(AccessControl.newBuilder()
                                                                                                                    .setMembers(AccessControl.AccessRequired.MEMBER)
                                                                                                                    .setAttributes(AccessControl.AccessRequired.MEMBER))
                                                                                     .setTitle(ByteString.copyFromUtf8("Some title"))
                                                                                     .setAvatar(avatarFor(groupPublicParams.getGroupIdentifier().serialize()))
                                                                                     .setVersion(0)
                                                                                     .addMembers(Member.newBuilder()
                                                                                                       .setUserId(ByteString.copyFrom(validUserPresentation.getUuidCiphertext().serialize()))
                                                                                                       .setProfileKey(ByteString.copyFrom(validUserPresentation.getProfileKeyCiphertext().serialize()))
                                                                                                       .setPresentation(ByteString.copyFrom(validUserPresentation.serialize()))
                                                                                                       .setRole(Member.Role.ADMINISTRATOR)
                                                                                                       .setJoinedAtVersion(0)
                                                                                                       .build())
                                                                                     .addMembers(Member.newBuilder()
                                                                                                       .setUserId(ByteString.copyFrom(validUserTwoPresentation.getUuidCiphertext().serialize()))
                                                                                                       .setProfileKey(ByteString.copyFrom(validUserTwoPresentation.getProfileKeyCiphertext().serialize()))
                                                                                                       .setPresentation(ByteString.copyFrom(validUserTwoPresentation.serialize()))
                                                                                                       .setRole(Member.Role.DEFAULT)
                                                                                                       .setJoinedAtVersion(0)
                                                                                                       .build())
                                                                                     .build();

  @Rule
  public final ResourceTestRule resources = ResourceTestRule.builder()
                                                            .addProvider(AuthHelper.getAuthFilter())
                                                            .addProvider(new AuthValueFactoryProvider.Binder<>(GroupUser.class))
                                                            .addProvider(new ProtocolBufferMessageBodyProvider())
                                                            .addProvider(new ProtocolBufferValidationErrorMessageBodyWriter())
                                                            .addProvider(new InvalidProtocolBufferExceptionMapper())
                                                            .setMapper(SystemMapper.getMapper())
                                                            .addResource(new GroupsController(groupsManager, AuthHelper.GROUPS_SERVER_KEY, policySigner, postPolicyGenerator, getGroupConfiguration(), groupCredentialGenerator))
                                                            .build();

  protected GroupConfiguration getGroupConfiguration() {
    final GroupConfiguration groupConfiguration = new GroupConfiguration();
    groupConfiguration.setMaxGroupSize(42);
    groupConfiguration.setMaxGroupTitleLengthBytes(1024);
    return groupConfiguration;
  }

  protected String avatarFor(byte[] groupId) {
    byte[] object = new byte[16];
    new SecureRandom().nextBytes(object);

    return "groups/" + Base64.encodeBase64URLSafeString(groupId) + "/" + Base64.encodeBase64URLSafeString(object);
  }

  @Before
  public void resetGroupsManager() {
    reset(groupsManager);
  }
}
