/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.configuration;

import com.fasterxml.jackson.annotation.JsonProperty;

import jakarta.validation.constraints.NotEmpty;

public class BigTableConfiguration {

  @JsonProperty
  @NotEmpty
  private String projectId;

  @JsonProperty
  @NotEmpty
  private String instanceId;

  @JsonProperty
  @NotEmpty
  private String contactManifestsTableId;

  @JsonProperty
  @NotEmpty
  private String contactsTableId;

  @JsonProperty
  @NotEmpty
  private String groupsTableId;

  @JsonProperty
  @NotEmpty
  private String groupLogsTableId;


  public String getProjectId() {
    return projectId;
  }

  public String getInstanceId() {
    return instanceId;
  }

  public String getContactManifestsTableId() {
    return contactManifestsTableId;
  }

  public String getContactsTableId() {
    return contactsTableId;
  }

  public String getGroupsTableId() {
    return groupsTableId;
  }

  public String getGroupLogsTableId() {
    return groupLogsTableId;
  }
}
