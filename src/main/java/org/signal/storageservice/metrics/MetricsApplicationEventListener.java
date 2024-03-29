/*
 * Copyright 2013-2022 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.metrics;

import org.glassfish.jersey.server.monitoring.ApplicationEvent;
import org.glassfish.jersey.server.monitoring.ApplicationEventListener;
import org.glassfish.jersey.server.monitoring.RequestEvent;
import org.glassfish.jersey.server.monitoring.RequestEventListener;

/**
 * Delegates request events to a listener that captures and reports request-level metrics.
 */
public class MetricsApplicationEventListener implements ApplicationEventListener {

  private final MetricsRequestEventListener metricsRequestEventListener = new MetricsRequestEventListener();

  @Override
  public void onEvent(final ApplicationEvent event) {
  }

  @Override
  public RequestEventListener onRequest(final RequestEvent requestEvent) {
    return metricsRequestEventListener;
  }
}
