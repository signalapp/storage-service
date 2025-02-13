/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.util;

import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.google.common.collect.ImmutableMap;
import io.dropwizard.auth.AuthFilter;
import io.dropwizard.auth.PolymorphicAuthDynamicFeature;
import io.dropwizard.auth.basic.BasicCredentialAuthFilter;
import io.dropwizard.auth.basic.BasicCredentials;
import java.security.Principal;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.UUID;
import org.apache.commons.codec.binary.Hex;
import org.signal.libsignal.protocol.ServiceId.Aci;
import org.signal.libsignal.protocol.ServiceId.Pni;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.ServerSecretParams;
import org.signal.libsignal.zkgroup.VerificationFailedException;
import org.signal.libsignal.zkgroup.auth.AuthCredentialPresentation;
import org.signal.libsignal.zkgroup.auth.AuthCredentialWithPni;
import org.signal.libsignal.zkgroup.auth.AuthCredentialWithPniResponse;
import org.signal.libsignal.zkgroup.auth.ClientZkAuthOperations;
import org.signal.libsignal.zkgroup.auth.ServerZkAuthOperations;
import org.signal.libsignal.zkgroup.groups.GroupSecretParams;
import org.signal.libsignal.zkgroup.profiles.ClientZkProfileOperations;
import org.signal.libsignal.zkgroup.profiles.ExpiringProfileKeyCredential;
import org.signal.libsignal.zkgroup.profiles.ExpiringProfileKeyCredentialResponse;
import org.signal.libsignal.zkgroup.profiles.ProfileKey;
import org.signal.libsignal.zkgroup.profiles.ProfileKeyCredentialRequestContext;
import org.signal.libsignal.zkgroup.profiles.ServerZkProfileOperations;
import org.signal.storageservice.auth.ExternalServiceCredentialValidator;
import org.signal.storageservice.auth.GroupUser;
import org.signal.storageservice.auth.GroupUserAuthenticator;
import org.signal.storageservice.auth.User;
import org.signal.storageservice.auth.UserAuthenticator;

public class AuthHelper {

  public static final Aci VALID_USER = new Aci(UUID.randomUUID());
  public static final Pni VALID_USER_PNI = new Pni(UUID.randomUUID());
  public static final byte[] VALID_USER_PROFILE_KEY = new byte[32];
  public static final String VALID_PASSWORD = "foo";

  public static final Aci VALID_USER_TWO = new Aci(UUID.randomUUID());
  public static final Pni VALID_USER_TWO_PNI = new Pni(UUID.randomUUID());
  public static final byte[] VALID_USER_TWO_PROFILE_KEY = new byte[32];

  public static final Aci VALID_USER_THREE = new Aci(UUID.randomUUID());
  public static final Pni VALID_USER_THREE_PNI = new Pni(UUID.randomUUID());
  public static final byte[] VALID_USER_THREE_PROFILE_KEY = new byte[32];

  public static final Aci VALID_USER_FOUR = new Aci(UUID.randomUUID());
  public static final Pni VALID_USER_FOUR_PNI = new Pni(UUID.randomUUID());
  public static final byte[] VALID_USER_FOUR_PROFILE_KEY = new byte[32];

  public static final Aci INVALID_USER = new Aci(UUID.randomUUID());
  public static final String INVALID_PASSWORD = "bar";

  public static ExternalServiceCredentialValidator CREDENTIAL_VALIDATOR =
      mock(ExternalServiceCredentialValidator.class);

  public static final ServerSecretParams GROUPS_SERVER_KEY = ServerSecretParams.generate();
  public static final AuthCredentialWithPni VALID_USER_AUTH_CREDENTIAL;
  public static final AuthCredentialWithPni VALID_USER_TWO_AUTH_CREDENTIAL;
  public static final AuthCredentialWithPni VALID_USER_THREE_AUTH_CREDENTIAL;
  public static final AuthCredentialWithPni VALID_USER_FOUR_AUTH_CREDENTIAL;

  public static final ExpiringProfileKeyCredential VALID_USER_PROFILE_CREDENTIAL;
  public static final ExpiringProfileKeyCredential VALID_USER_TWO_PROFILE_CREDENTIAL;
  public static final ExpiringProfileKeyCredential VALID_USER_THREE_PROFILE_CREDENTIAL;
  public static final ExpiringProfileKeyCredential VALID_USER_FOUR_PROFILE_CREDENTIAL;

  static {
    try {
      int redemptionTime = Util.currentDaysSinceEpoch();
      Instant redemptionInstant = Instant.EPOCH.plus(Duration.ofDays(redemptionTime));
      AuthCredentialWithPniResponse validUserPniResponse = new ServerZkAuthOperations(
          GROUPS_SERVER_KEY).issueAuthCredentialWithPniZkc(VALID_USER, VALID_USER_PNI, redemptionInstant);
      AuthCredentialWithPniResponse validUserTwoPniResponse = new ServerZkAuthOperations(
          GROUPS_SERVER_KEY).issueAuthCredentialWithPniZkc(VALID_USER_TWO, VALID_USER_TWO_PNI, redemptionInstant);
      AuthCredentialWithPniResponse validUserThreePniResponse = new ServerZkAuthOperations(
          GROUPS_SERVER_KEY).issueAuthCredentialWithPniZkc(VALID_USER_THREE, VALID_USER_THREE_PNI, redemptionInstant);
      AuthCredentialWithPniResponse validUserFourPniResponse = new ServerZkAuthOperations(
          GROUPS_SERVER_KEY).issueAuthCredentialWithPniZkc(VALID_USER_FOUR, VALID_USER_FOUR_PNI, redemptionInstant);

      VALID_USER_AUTH_CREDENTIAL = new ClientZkAuthOperations(
          GROUPS_SERVER_KEY.getPublicParams()).receiveAuthCredentialWithPniAsServiceId(VALID_USER, VALID_USER_PNI,
          redemptionInstant.getEpochSecond(), validUserPniResponse);
      VALID_USER_TWO_AUTH_CREDENTIAL = new ClientZkAuthOperations(
          GROUPS_SERVER_KEY.getPublicParams()).receiveAuthCredentialWithPniAsServiceId(VALID_USER_TWO,
          VALID_USER_TWO_PNI, redemptionInstant.getEpochSecond(), validUserTwoPniResponse);
      VALID_USER_THREE_AUTH_CREDENTIAL = new ClientZkAuthOperations(
          GROUPS_SERVER_KEY.getPublicParams()).receiveAuthCredentialWithPniAsServiceId(VALID_USER_THREE,
          VALID_USER_THREE_PNI, redemptionInstant.getEpochSecond(), validUserThreePniResponse);
      VALID_USER_FOUR_AUTH_CREDENTIAL = new ClientZkAuthOperations(
          GROUPS_SERVER_KEY.getPublicParams()).receiveAuthCredentialWithPniAsServiceId(VALID_USER_FOUR,
          VALID_USER_FOUR_PNI, redemptionInstant.getEpochSecond(), validUserFourPniResponse);

      final SecureRandom secureRandom = new SecureRandom();
      secureRandom.nextBytes(VALID_USER_PROFILE_KEY);
      secureRandom.nextBytes(VALID_USER_TWO_PROFILE_KEY);
      secureRandom.nextBytes(VALID_USER_THREE_PROFILE_KEY);
      secureRandom.nextBytes(VALID_USER_FOUR_PROFILE_KEY);

      ProfileKey validUserProfileKey = new ProfileKey(VALID_USER_PROFILE_KEY);
      ProfileKey validUserTwoProfileKey = new ProfileKey(VALID_USER_TWO_PROFILE_KEY);
      ProfileKey validUserThreeProfileKey = new ProfileKey(VALID_USER_THREE_PROFILE_KEY);
      ProfileKey validUserFourProfileKey = new ProfileKey(VALID_USER_FOUR_PROFILE_KEY);

      ProfileKeyCredentialRequestContext validUserProfileKeyCredentialRequestContext = new ClientZkProfileOperations(
          GROUPS_SERVER_KEY.getPublicParams()).createProfileKeyCredentialRequestContext(VALID_USER,
          validUserProfileKey);
      ProfileKeyCredentialRequestContext validUserTwoProfileKeyCredentialRequestContext = new ClientZkProfileOperations(
          GROUPS_SERVER_KEY.getPublicParams()).createProfileKeyCredentialRequestContext(VALID_USER_TWO,
          validUserTwoProfileKey);
      ProfileKeyCredentialRequestContext validUserThreeProfileKeyCredentialRequestContext = new ClientZkProfileOperations(
          GROUPS_SERVER_KEY.getPublicParams()).createProfileKeyCredentialRequestContext(VALID_USER_THREE,
          validUserThreeProfileKey);
      ProfileKeyCredentialRequestContext validUserFourProfileKeyCredentialRequestContext = new ClientZkProfileOperations(
          GROUPS_SERVER_KEY.getPublicParams()).createProfileKeyCredentialRequestContext(VALID_USER_FOUR,
          validUserFourProfileKey);

      Instant expiration = redemptionInstant.plus(1, ChronoUnit.DAYS);

      ExpiringProfileKeyCredentialResponse validUserProfileKeyCredentialResponse = new ServerZkProfileOperations(
          GROUPS_SERVER_KEY).issueExpiringProfileKeyCredential(validUserProfileKeyCredentialRequestContext.getRequest(),
          VALID_USER, validUserProfileKey.getCommitment(VALID_USER), expiration);
      ExpiringProfileKeyCredentialResponse validUserTwoProfileKeyCredentialResponse = new ServerZkProfileOperations(
          GROUPS_SERVER_KEY).issueExpiringProfileKeyCredential(
          validUserTwoProfileKeyCredentialRequestContext.getRequest(), VALID_USER_TWO,
          validUserTwoProfileKey.getCommitment(VALID_USER_TWO), expiration);
      ExpiringProfileKeyCredentialResponse validUserThreeProfileKeyCredentialResponse = new ServerZkProfileOperations(
          GROUPS_SERVER_KEY).issueExpiringProfileKeyCredential(
          validUserThreeProfileKeyCredentialRequestContext.getRequest(), VALID_USER_THREE,
          validUserThreeProfileKey.getCommitment(VALID_USER_THREE), expiration);
      ExpiringProfileKeyCredentialResponse validUserFourProfileKeyCredentialResponse = new ServerZkProfileOperations(
          GROUPS_SERVER_KEY).issueExpiringProfileKeyCredential(
          validUserFourProfileKeyCredentialRequestContext.getRequest(), VALID_USER_FOUR,
          validUserFourProfileKey.getCommitment(VALID_USER_FOUR), expiration);

      VALID_USER_PROFILE_CREDENTIAL = new ClientZkProfileOperations(
          GROUPS_SERVER_KEY.getPublicParams()).receiveExpiringProfileKeyCredential(
          validUserProfileKeyCredentialRequestContext, validUserProfileKeyCredentialResponse, redemptionInstant);
      VALID_USER_TWO_PROFILE_CREDENTIAL = new ClientZkProfileOperations(
          GROUPS_SERVER_KEY.getPublicParams()).receiveExpiringProfileKeyCredential(
          validUserTwoProfileKeyCredentialRequestContext, validUserTwoProfileKeyCredentialResponse, redemptionInstant);
      VALID_USER_THREE_PROFILE_CREDENTIAL = new ClientZkProfileOperations(
          GROUPS_SERVER_KEY.getPublicParams()).receiveExpiringProfileKeyCredential(
          validUserThreeProfileKeyCredentialRequestContext, validUserThreeProfileKeyCredentialResponse,
          redemptionInstant);
      VALID_USER_FOUR_PROFILE_CREDENTIAL = new ClientZkProfileOperations(
          GROUPS_SERVER_KEY.getPublicParams()).receiveExpiringProfileKeyCredential(
          validUserFourProfileKeyCredentialRequestContext, validUserFourProfileKeyCredentialResponse,
          redemptionInstant);
    } catch (VerificationFailedException | InvalidInputException e) {
      throw new AssertionError(e);
    }
  }

  public static PolymorphicAuthDynamicFeature<Principal> getAuthFilter() {
    when(
        CREDENTIAL_VALIDATOR.isValid(eq(VALID_PASSWORD), eq(VALID_USER.getRawUUID().toString()), anyLong())).thenReturn(
        true);

    AuthFilter<BasicCredentials, User> userAuthFilter = new BasicCredentialAuthFilter.Builder<User>().setAuthenticator(
        new UserAuthenticator(CREDENTIAL_VALIDATOR)).buildAuthFilter();
    AuthFilter<BasicCredentials, GroupUser> groupUserAuthFilter = new BasicCredentialAuthFilter.Builder<GroupUser>().setAuthenticator(
        new GroupUserAuthenticator(new ServerZkAuthOperations(GROUPS_SERVER_KEY))).buildAuthFilter();

    return new PolymorphicAuthDynamicFeature<>(
        ImmutableMap.of(User.class, userAuthFilter, GroupUser.class, groupUserAuthFilter));
  }

  public static String getAuthHeader(Aci user, String password) {
    return "Basic " + Base64.getEncoder().encodeToString((user.getRawUUID() + ":" + password).getBytes());
  }

  public static String getAuthHeader(GroupSecretParams groupSecretParams, AuthCredentialWithPni credential) {
    return getAuthHeader(groupSecretParams,
        new ClientZkAuthOperations(GROUPS_SERVER_KEY.getPublicParams()).createAuthCredentialPresentation(
            groupSecretParams, credential));
  }

  private static String getAuthHeader(final GroupSecretParams groupSecretParams,
      final AuthCredentialPresentation presentation) {
    return "Basic " + Base64.getEncoder().encodeToString(
        (Hex.encodeHexString(groupSecretParams.getPublicParams().serialize()) + ":" + Hex.encodeHexString(
            presentation.serialize())).getBytes());
  }
}
