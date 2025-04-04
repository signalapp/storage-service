/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.dropwizard.core.Configuration;
import org.signal.storageservice.configuration.AuthenticationConfiguration;
import org.signal.storageservice.configuration.BigTableConfiguration;
import org.signal.storageservice.configuration.CdnConfiguration;
import org.signal.storageservice.configuration.DatadogConfiguration;
import org.signal.storageservice.configuration.GroupConfiguration;
import org.signal.storageservice.configuration.WarmupConfiguration;
import org.signal.storageservice.configuration.ZkConfiguration;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotNull;

public class StorageServiceConfiguration extends Configuration {

  @JsonProperty
  @Valid
  @NotNull
  private BigTableConfiguration bigtable;

  @JsonProperty
  @Valid
  @NotNull
  private AuthenticationConfiguration authentication;

  @JsonProperty
  @Valid
  @NotNull
  private ZkConfiguration zkConfig;

  @JsonProperty
  @Valid
  @NotNull
  private CdnConfiguration cdn;

  @JsonProperty
  @Valid
  @NotNull
  private GroupConfiguration group;

  @JsonProperty
  @Valid
  @NotNull
  private DatadogConfiguration datadog;

  @JsonProperty
  @Valid
  @NotNull
  private WarmupConfiguration warmup = new WarmupConfiguration(5);

  public BigTableConfiguration getBigTableConfiguration() {
    return bigtable;
  }

  public AuthenticationConfiguration getAuthenticationConfiguration() {
    return authentication;
  }

  public ZkConfiguration getZkConfiguration() {
    return zkConfig;
  }

  public CdnConfiguration getCdnConfiguration() {
    return cdn;
  }

  public GroupConfiguration getGroupConfiguration() {
    return group;
  }

  public DatadogConfiguration getDatadogConfiguration() {
    return datadog;
  }

  public WarmupConfiguration getWarmUpConfiguration() {
    return warmup;
  }
}
