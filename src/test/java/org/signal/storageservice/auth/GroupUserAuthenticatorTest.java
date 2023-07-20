/*
 * Copyright 2013-2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.auth;

import com.google.protobuf.ByteString;
import io.dropwizard.auth.basic.BasicCredentials;
import org.apache.commons.codec.binary.Hex;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.signal.libsignal.protocol.ServiceId.Aci;
import org.signal.libsignal.protocol.ServiceId.Pni;
import org.signal.libsignal.zkgroup.ServerSecretParams;
import org.signal.libsignal.zkgroup.VerificationFailedException;
import org.signal.libsignal.zkgroup.auth.AuthCredential;
import org.signal.libsignal.zkgroup.auth.AuthCredentialPresentation;
import org.signal.libsignal.zkgroup.auth.AuthCredentialResponse;
import org.signal.libsignal.zkgroup.auth.AuthCredentialWithPni;
import org.signal.libsignal.zkgroup.auth.AuthCredentialWithPniResponse;
import org.signal.libsignal.zkgroup.auth.ClientZkAuthOperations;
import org.signal.libsignal.zkgroup.auth.ServerZkAuthOperations;
import org.signal.libsignal.zkgroup.groups.GroupPublicParams;
import org.signal.libsignal.zkgroup.groups.GroupSecretParams;

import javax.annotation.Nullable;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertAll;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class GroupUserAuthenticatorTest {

  private static final ServerSecretParams SERVER_SECRET_PARAMS = ServerSecretParams.generate();

  private static final GroupSecretParams GROUP_SECRET_PARAMS = GroupSecretParams.generate();
  private static final GroupPublicParams GROUP_PUBLIC_PARAMS = GROUP_SECRET_PARAMS.getPublicParams();

  private static final byte[] GROUP_ID = GROUP_PUBLIC_PARAMS.serialize();
  private static final byte[] GROUP_PUBLIC_KEY = GROUP_PUBLIC_PARAMS.serialize();

  private GroupUserAuthenticator groupUserAuthenticator;

  @BeforeEach
  void setUp() {
    groupUserAuthenticator = new GroupUserAuthenticator(new ServerZkAuthOperations(SERVER_SECRET_PARAMS));
  }

  @ParameterizedTest
  @MethodSource
  void authenticate(final byte[] presentation, final GroupUser expectedGroupUser) {
    final BasicCredentials basicCredentials =
        new BasicCredentials(Hex.encodeHexString(GROUP_PUBLIC_KEY), Hex.encodeHexString(presentation));

    final Optional<GroupUser> maybeAuthenticatedUser = groupUserAuthenticator.authenticate(basicCredentials);

    assertTrue(maybeAuthenticatedUser.isPresent());
    assertGroupUserEqual(expectedGroupUser, maybeAuthenticatedUser.get());
  }

  private static void assertGroupUserEqual(final GroupUser expected, final GroupUser actual) {
    assertAll(
        () -> assertEquals(expected.getAciCiphertext(), actual.getAciCiphertext()),
        () -> assertEquals(expected.getPniCiphertext(), actual.getPniCiphertext())
    );
  }

  private static Stream<Arguments> authenticate() throws VerificationFailedException {
    final Aci aci = new Aci(UUID.randomUUID());
    final Pni pni = new Pni(UUID.randomUUID());

    final Instant redemptionInstant = Instant.now().truncatedTo(ChronoUnit.DAYS);
    final int redemptionDaysSinceEpoch = (int) ChronoUnit.DAYS.between(Instant.EPOCH, redemptionInstant);

    final ServerZkAuthOperations serverZkAuthOperations = new ServerZkAuthOperations(SERVER_SECRET_PARAMS);
    final ClientZkAuthOperations clientZkAuthOperations = new ClientZkAuthOperations(SERVER_SECRET_PARAMS.getPublicParams());

    final byte[] aciAuthCredentialPresentation;
    final GroupUser expectedAciGroupUser;
    {
      final AuthCredentialResponse authCredentialResponse = serverZkAuthOperations.issueAuthCredential(aci, redemptionDaysSinceEpoch);
      final AuthCredential authCredential = clientZkAuthOperations.receiveAuthCredential(aci, redemptionDaysSinceEpoch, authCredentialResponse);
      final AuthCredentialPresentation authCredentialPresentation = clientZkAuthOperations.createAuthCredentialPresentation(GROUP_SECRET_PARAMS, authCredential);

      aciAuthCredentialPresentation = authCredentialPresentation.serialize();
      expectedAciGroupUser = new GroupUser(
          ByteString.copyFrom(authCredentialPresentation.getUuidCiphertext().serialize()),
          null,
          ByteString.copyFrom(GROUP_PUBLIC_KEY),
          ByteString.copyFrom(GROUP_ID));
    }

    final byte[] aciPniAuthCredentialPresentation;
    final GroupUser expectedAciPniGroupUser;
    {
      final AuthCredentialWithPniResponse authCredentialWithPniResponse = serverZkAuthOperations.issueAuthCredentialWithPniAsServiceId(aci, pni, redemptionInstant);
      final AuthCredentialWithPni authCredentialWithPni = clientZkAuthOperations.receiveAuthCredentialWithPniAsServiceId(aci, pni, redemptionInstant.getEpochSecond(), authCredentialWithPniResponse);
      final AuthCredentialPresentation authCredentialPresentation = clientZkAuthOperations.createAuthCredentialPresentation(GROUP_SECRET_PARAMS, authCredentialWithPni);

      aciPniAuthCredentialPresentation = authCredentialPresentation.serialize();
      expectedAciPniGroupUser = new GroupUser(
          ByteString.copyFrom(authCredentialPresentation.getUuidCiphertext().serialize()),
          ByteString.copyFrom(authCredentialPresentation.getPniCiphertext().serialize()),
          ByteString.copyFrom(GROUP_PUBLIC_KEY),
          ByteString.copyFrom(GROUP_ID));
    }

    return Stream.of(
        Arguments.of(aciAuthCredentialPresentation, expectedAciGroupUser),
        Arguments.of(aciPniAuthCredentialPresentation, expectedAciPniGroupUser)
    );
  }
}
