/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.controllers;

import javax.ws.rs.GET;
import javax.ws.rs.Path;

@Path("/ping")
public class HealthCheckController {

  @GET
  public String isAlive() {
    return "Pong";
  }

}
