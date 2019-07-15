/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.auth;

import io.dropwizard.auth.AuthenticationException;
import io.dropwizard.auth.Authenticator;
import io.dropwizard.auth.basic.BasicCredentials;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Optional;
import java.util.UUID;

public class UserAuthenticator implements Authenticator<BasicCredentials, User> {

  private final Logger logger = LoggerFactory.getLogger(UserAuthenticator.class);

  private final ExternalServiceCredentialValidator validator;

  public UserAuthenticator(ExternalServiceCredentialValidator validator) {
    this.validator = validator;
  }

  @Override
  public Optional<User> authenticate(BasicCredentials basicCredentials) throws AuthenticationException {
    if (validator.isValid(basicCredentials.getPassword(), basicCredentials.getUsername(), System.currentTimeMillis())) {
      try {
        UUID userId = UUID.fromString(basicCredentials.getUsername());
        return Optional.of(new User(userId));
      } catch (IllegalArgumentException e) {
        logger.warn("Successful authentication of non-UUID?", e);
        return Optional.empty();
      }
    }

    return Optional.empty();
  }
}
