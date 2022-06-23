/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.auth;

import com.google.protobuf.ByteString;
import io.dropwizard.auth.Authenticator;
import io.dropwizard.auth.basic.BasicCredentials;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.signal.libsignal.zkgroup.InvalidInputException;
import org.signal.libsignal.zkgroup.InvalidRedemptionTimeException;
import org.signal.libsignal.zkgroup.VerificationFailedException;
import org.signal.libsignal.zkgroup.auth.AuthCredentialPresentation;
import org.signal.libsignal.zkgroup.auth.ServerZkAuthOperations;
import org.signal.libsignal.zkgroup.groups.GroupPublicParams;

import java.util.Optional;

public class GroupUserAuthenticator implements Authenticator<BasicCredentials, GroupUser> {

  private ServerZkAuthOperations serverZkAuthOperations;

  public GroupUserAuthenticator(ServerZkAuthOperations serverZkAuthOperations) {
    this.serverZkAuthOperations = serverZkAuthOperations;
  }

  @Override
  public Optional<GroupUser> authenticate(BasicCredentials basicCredentials) {
    try {
      String encodedGroupPublicKey = basicCredentials.getUsername();
      String encodedPresentation   = basicCredentials.getPassword();

      GroupPublicParams          groupPublicKey = new GroupPublicParams(Hex.decodeHex(encodedGroupPublicKey));
      AuthCredentialPresentation presentation   = new AuthCredentialPresentation(Hex.decodeHex(encodedPresentation));

      serverZkAuthOperations.verifyAuthCredentialPresentation(groupPublicKey, presentation);

      return Optional.of(new GroupUser(ByteString.copyFrom(presentation.getUuidCiphertext().serialize()),
                                       presentation.getPniCiphertext() != null ? ByteString.copyFrom(presentation.getPniCiphertext().serialize()) : null,
                                       ByteString.copyFrom(groupPublicKey.serialize()),
                                       ByteString.copyFrom(groupPublicKey.getGroupIdentifier().serialize())));

    } catch (DecoderException | VerificationFailedException | InvalidInputException | InvalidRedemptionTimeException e) {
      return Optional.empty();
    }
  }
}
