/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.auth;

import com.fasterxml.jackson.annotation.JsonIgnore;

import javax.security.auth.Subject;
import java.security.Principal;
import java.util.UUID;

public class User implements Principal {

  private final UUID uuid;

  public User(UUID uuid) {
    this.uuid = uuid;
  }

  public UUID getUuid() {
    return uuid;
  }

  // Principal implementation

  @JsonIgnore
  @Override
  public String getName() {
    return null;
  }

  @JsonIgnore
  @Override
  public boolean implies(Subject subject) {
    return false;
  }

  @Override
  public boolean equals(Object other) {
    if (other == null           ) return false;
    if (!(other instanceof User)) return false;

    User that = (User)other;

    return this.uuid.equals(that.uuid);
  }

  @Override
  public int hashCode() {
    return uuid.hashCode();
  }
}
