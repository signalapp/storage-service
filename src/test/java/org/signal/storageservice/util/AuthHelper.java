/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.util;

import com.google.common.collect.ImmutableMap;
import io.dropwizard.auth.AuthFilter;
import io.dropwizard.auth.PolymorphicAuthDynamicFeature;
import io.dropwizard.auth.basic.BasicCredentialAuthFilter;
import io.dropwizard.auth.basic.BasicCredentials;
import org.apache.commons.codec.binary.Hex;
import org.signal.storageservice.auth.ExternalServiceCredentialValidator;
import org.signal.storageservice.auth.GroupUser;
import org.signal.storageservice.auth.GroupUserAuthenticator;
import org.signal.storageservice.auth.User;
import org.signal.storageservice.auth.UserAuthenticator;
import org.signal.zkgroup.InvalidInputException;
import org.signal.zkgroup.ServerSecretParams;
import org.signal.zkgroup.VerificationFailedException;
import org.signal.zkgroup.auth.AuthCredential;
import org.signal.zkgroup.auth.AuthCredentialPresentation;
import org.signal.zkgroup.auth.AuthCredentialResponse;
import org.signal.zkgroup.auth.ClientZkAuthOperations;
import org.signal.zkgroup.auth.ServerZkAuthOperations;
import org.signal.zkgroup.groups.GroupSecretParams;
import org.signal.zkgroup.profiles.ClientZkProfileOperations;
import org.signal.zkgroup.profiles.ProfileKey;
import org.signal.zkgroup.profiles.ProfileKeyCredential;
import org.signal.zkgroup.profiles.ProfileKeyCredentialRequestContext;
import org.signal.zkgroup.profiles.ProfileKeyCredentialResponse;
import org.signal.zkgroup.profiles.ServerZkProfileOperations;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AuthHelper {
  public static final String VALID_USER             = UUID.randomUUID().toString();
  public static final byte[] VALID_USER_PROFILE_KEY = new byte[32];
  public static final String VALID_PASSWORD         = "foo";

  public static final String VALID_USER_TWO             = UUID.randomUUID().toString();
  public static final byte[] VALID_USER_TWO_PROFILE_KEY = new byte[32];
  public static final String VALID_PASSWORD_TWO         = "bar";

  public static final String VALID_USER_THREE             = UUID.randomUUID().toString();
  public static final byte[] VALID_USER_THREE_PROFILE_KEY = new byte[32];
  public static final String VALID_PASSWORD_THREE         = "baz";

  public static final String INVALID_USER     = UUID.randomUUID().toString();
  public static final String INVALID_PASSWORD = "bar";

  public static ExternalServiceCredentialValidator CREDENTIAL_VALIDATOR = mock(ExternalServiceCredentialValidator.class);

  public static final ServerSecretParams     GROUPS_SERVER_KEY          = ServerSecretParams.generate();
  public static final AuthCredential         VALID_USER_AUTH_CREDENTIAL;
  public static final AuthCredential         VALID_USER_TWO_AUTH_CREDENTIAL;
  public static final AuthCredential         VALID_USER_THREE_AUTH_CREDENTIAL;

  public static final ProfileKeyCredential   VALID_USER_PROFILE_CREDENTIAL;
  public static final ProfileKeyCredential   VALID_USER_TWO_PROFILE_CREDENTIAL;
  public static final ProfileKeyCredential   VALID_USER_THREE_PROFILE_CREDENTIAL;

  static {
    try {
      int                    redemptionTime       = Util.currentDaysSinceEpoch();
      AuthCredentialResponse validUserResponse    = new ServerZkAuthOperations(GROUPS_SERVER_KEY).issueAuthCredential(UUID.fromString(VALID_USER    ), redemptionTime);
      AuthCredentialResponse validUserTwoResponse = new ServerZkAuthOperations(GROUPS_SERVER_KEY).issueAuthCredential(UUID.fromString(VALID_USER_TWO), redemptionTime);
      AuthCredentialResponse validUserThreeResponse = new ServerZkAuthOperations(GROUPS_SERVER_KEY).issueAuthCredential(UUID.fromString(VALID_USER_THREE), redemptionTime);

      VALID_USER_AUTH_CREDENTIAL = new ClientZkAuthOperations(GROUPS_SERVER_KEY.getPublicParams()).receiveAuthCredential(UUID.fromString(VALID_USER), redemptionTime, validUserResponse);
      VALID_USER_TWO_AUTH_CREDENTIAL = new ClientZkAuthOperations(GROUPS_SERVER_KEY.getPublicParams()).receiveAuthCredential(UUID.fromString(VALID_USER_TWO), redemptionTime, validUserTwoResponse);
      VALID_USER_THREE_AUTH_CREDENTIAL = new ClientZkAuthOperations(GROUPS_SERVER_KEY.getPublicParams()).receiveAuthCredential(UUID.fromString(VALID_USER_THREE), redemptionTime, validUserThreeResponse);

      new SecureRandom().nextBytes(VALID_USER_PROFILE_KEY);
      new SecureRandom().nextBytes(VALID_USER_TWO_PROFILE_KEY);

      ProfileKey validUserProfileKey    = new ProfileKey(VALID_USER_PROFILE_KEY    );
      ProfileKey validUserTwoProfileKey = new ProfileKey(VALID_USER_TWO_PROFILE_KEY);
      ProfileKey validUserThreeProfileKey = new ProfileKey(VALID_USER_THREE_PROFILE_KEY);

      ProfileKeyCredentialRequestContext validUserProfileKeyCredentialRequestContext = new ClientZkProfileOperations(GROUPS_SERVER_KEY.getPublicParams()).createProfileKeyCredentialRequestContext(UUID.fromString(VALID_USER), validUserProfileKey);
      ProfileKeyCredentialRequestContext validUserTwoProfileKeyCredentialRequestContext = new ClientZkProfileOperations(GROUPS_SERVER_KEY.getPublicParams()).createProfileKeyCredentialRequestContext(UUID.fromString(VALID_USER_TWO), validUserTwoProfileKey);
      ProfileKeyCredentialRequestContext validUserThreeProfileKeyCredentialRequestContext = new ClientZkProfileOperations(GROUPS_SERVER_KEY.getPublicParams()).createProfileKeyCredentialRequestContext(UUID.fromString(VALID_USER_THREE), validUserThreeProfileKey);

      ProfileKeyCredentialResponse       validUserProfileKeyCredentialResponse       = new ServerZkProfileOperations(GROUPS_SERVER_KEY).issueProfileKeyCredential(validUserProfileKeyCredentialRequestContext.getRequest(), UUID.fromString(VALID_USER), validUserProfileKey.getCommitment(UUID.fromString(VALID_USER)));
      ProfileKeyCredentialResponse       validUserTwoProfileKeyCredentialResponse    = new ServerZkProfileOperations(GROUPS_SERVER_KEY).issueProfileKeyCredential(validUserTwoProfileKeyCredentialRequestContext.getRequest(), UUID.fromString(VALID_USER_TWO), validUserTwoProfileKey.getCommitment(UUID.fromString(VALID_USER_TWO)));
      ProfileKeyCredentialResponse       validUserThreeProfileKeyCredentialResponse    = new ServerZkProfileOperations(GROUPS_SERVER_KEY).issueProfileKeyCredential(validUserThreeProfileKeyCredentialRequestContext.getRequest(), UUID.fromString(VALID_USER_THREE), validUserThreeProfileKey.getCommitment(UUID.fromString(VALID_USER_THREE)));

      VALID_USER_PROFILE_CREDENTIAL     = new ClientZkProfileOperations(GROUPS_SERVER_KEY.getPublicParams()).receiveProfileKeyCredential(validUserProfileKeyCredentialRequestContext, validUserProfileKeyCredentialResponse      );
      VALID_USER_TWO_PROFILE_CREDENTIAL = new ClientZkProfileOperations(GROUPS_SERVER_KEY.getPublicParams()).receiveProfileKeyCredential(validUserTwoProfileKeyCredentialRequestContext, validUserTwoProfileKeyCredentialResponse);
      VALID_USER_THREE_PROFILE_CREDENTIAL = new ClientZkProfileOperations(GROUPS_SERVER_KEY.getPublicParams()).receiveProfileKeyCredential(validUserThreeProfileKeyCredentialRequestContext, validUserThreeProfileKeyCredentialResponse);
    } catch (VerificationFailedException | InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public static PolymorphicAuthDynamicFeature getAuthFilter() {
    when(CREDENTIAL_VALIDATOR.isValid(eq(VALID_PASSWORD), eq(VALID_USER), anyLong())).thenReturn(true);
    when(CREDENTIAL_VALIDATOR.isValid(eq(INVALID_USER), eq(INVALID_PASSWORD), anyLong())).thenReturn(false);

    AuthFilter<BasicCredentials, User>      userAuthFilter      = new BasicCredentialAuthFilter.Builder<User>().setAuthenticator(new UserAuthenticator(CREDENTIAL_VALIDATOR)).buildAuthFilter       ();
    AuthFilter<BasicCredentials, GroupUser> groupUserAuthFilter = new BasicCredentialAuthFilter.Builder<GroupUser>().setAuthenticator(new GroupUserAuthenticator(new ServerZkAuthOperations(GROUPS_SERVER_KEY))).buildAuthFilter();

    return new PolymorphicAuthDynamicFeature<>(ImmutableMap.of(User.class, userAuthFilter, GroupUser.class, groupUserAuthFilter));
  }

  public static String getAuthHeader(String user, String password) {
    return "Basic " + Base64.getEncoder().encodeToString((user + ":" + password).getBytes());
  }

  public static String getAuthHeader(GroupSecretParams groupSecretParams, AuthCredential credential) {
    AuthCredentialPresentation presentation = new ClientZkAuthOperations(GROUPS_SERVER_KEY.getPublicParams()).createAuthCredentialPresentation(groupSecretParams, credential);
    return "Basic " + Base64.getEncoder().encodeToString((Hex.encodeHexString(groupSecretParams.getPublicParams().serialize()) + ":" + Hex.encodeHexString(presentation.serialize())).getBytes());
  }

}
