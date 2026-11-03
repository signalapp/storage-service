/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.configuration;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.JsonTypeName;
import com.google.cloud.bigtable.data.v2.BigtableDataClient;
import com.google.cloud.bigtable.data.v2.BigtableDataSettings;
import io.dropwizard.jackson.Discoverable;
import java.io.IOException;

import jakarta.validation.constraints.NotEmpty;

@JsonTypeName("default")
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, property = "type", defaultImpl = BigTableConfiguration.class)
public class BigTableConfiguration implements Discoverable {

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

  public BigtableDataClient buildDataClient() throws IOException {
    return BigtableDataClient.create(BigtableDataSettings.newBuilder()
        .setProjectId(getProjectId())
        .setInstanceId(getInstanceId())
        .build());
  }
}
