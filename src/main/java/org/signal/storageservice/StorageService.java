/*
 * Copyright 2020-2021 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice;

import static com.codahale.metrics.MetricRegistry.name;

import com.codahale.metrics.SharedMetricRegistries;
import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.google.cloud.bigtable.admin.v2.BigtableTableAdminClient;
import com.google.cloud.bigtable.admin.v2.BigtableTableAdminSettings;
import com.google.cloud.bigtable.data.v2.BigtableDataClient;
import com.google.cloud.bigtable.data.v2.BigtableDataSettings;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import io.dropwizard.Application;
import io.dropwizard.auth.AuthFilter;
import io.dropwizard.auth.PolymorphicAuthDynamicFeature;
import io.dropwizard.auth.PolymorphicAuthValueFactoryProvider;
import io.dropwizard.auth.basic.BasicCredentialAuthFilter;
import io.dropwizard.auth.basic.BasicCredentials;
import io.dropwizard.setup.Bootstrap;
import io.dropwizard.setup.Environment;
import java.time.Clock;
import java.util.List;
import org.signal.storageservice.auth.ExternalGroupCredentialGenerator;
import org.signal.storageservice.auth.ExternalServiceCredentialValidator;
import org.signal.storageservice.auth.GroupUser;
import org.signal.storageservice.auth.GroupUserAuthenticator;
import org.signal.storageservice.auth.User;
import org.signal.storageservice.auth.UserAuthenticator;
import org.signal.storageservice.controllers.BackupsController;
import org.signal.storageservice.controllers.GroupsController;
import org.signal.storageservice.controllers.HealthCheckController;
import org.signal.storageservice.controllers.StorageController;
import org.signal.storageservice.metrics.CpuUsageGauge;
import org.signal.storageservice.metrics.FileDescriptorGauge;
import org.signal.storageservice.metrics.FreeMemoryGauge;
import org.signal.storageservice.metrics.NetworkReceivedGauge;
import org.signal.storageservice.metrics.NetworkSentGauge;
import org.signal.storageservice.metrics.StorageMetrics;
import org.signal.storageservice.providers.CompletionExceptionMapper;
import org.signal.storageservice.providers.InvalidProtocolBufferExceptionMapper;
import org.signal.storageservice.providers.ProtocolBufferMessageBodyProvider;
import org.signal.storageservice.providers.ProtocolBufferValidationErrorMessageBodyWriter;
import org.signal.storageservice.s3.PolicySigner;
import org.signal.storageservice.s3.PostPolicyGenerator;
import org.signal.storageservice.storage.BackupsManager;
import org.signal.storageservice.storage.GroupsManager;
import org.signal.storageservice.storage.StorageManager;
import org.signal.storageservice.util.UncaughtExceptionHandler;
import org.signal.zkgroup.ServerSecretParams;
import org.signal.zkgroup.auth.ServerZkAuthOperations;

public class StorageService extends Application<StorageServiceConfiguration> {

  @Override
  public void initialize(Bootstrap<StorageServiceConfiguration> bootstrap) { }

  @Override
  public void run(StorageServiceConfiguration config, Environment environment) throws Exception {
    SharedMetricRegistries.add(StorageMetrics.NAME, environment.metrics());

    UncaughtExceptionHandler.register();

    BigtableTableAdminSettings bigtableTableAdminSettings = BigtableTableAdminSettings.newBuilder()
                                                                                      .setProjectId(config.getBigTableConfiguration().getProjectId())
                                                                                      .setInstanceId(config.getBigTableConfiguration().getInstanceId())
                                                                                      .build();
    BigtableTableAdminClient bigtableTableAdminClient = BigtableTableAdminClient.create(bigtableTableAdminSettings);

    BigtableDataSettings bigtableDataSettings = BigtableDataSettings.newBuilder()
                                                                    .setProjectId(config.getBigTableConfiguration().getProjectId())
                                                                    .setInstanceId(config.getBigTableConfiguration().getInstanceId())
                                                                    .build();
    BigtableDataClient bigtableDataClient = BigtableDataClient.create(bigtableDataSettings);
    ServerSecretParams serverSecretParams = new ServerSecretParams(config.getZkConfiguration().getServerSecret());
    StorageManager     storageManager     = new StorageManager(bigtableDataClient, config.getBigTableConfiguration().getContactManifestsTableId(), config.getBigTableConfiguration().getContactsTableId());
    GroupsManager      groupsManager      = new GroupsManager(bigtableDataClient, config.getBigTableConfiguration().getGroupsTableId(), config.getBigTableConfiguration().getGroupLogsTableId());
    BackupsManager backupsManager = new BackupsManager(bigtableTableAdminClient, config.getBigTableConfiguration().getClusterId(), List.of(
            config.getBigTableConfiguration().getContactManifestsTableId(),
            config.getBigTableConfiguration().getContactsTableId(),
            config.getBigTableConfiguration().getGroupLogsTableId(),
            config.getBigTableConfiguration().getGroupsTableId()));

    environment.getObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    environment.getObjectMapper().setVisibility(PropertyAccessor.ALL, JsonAutoDetect.Visibility.NONE);
    environment.getObjectMapper().setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY);

    environment.jersey().register(ProtocolBufferMessageBodyProvider.class);
    environment.jersey().register(ProtocolBufferValidationErrorMessageBodyWriter.class);
    environment.jersey().register(InvalidProtocolBufferExceptionMapper.class);
    environment.jersey().register(CompletionExceptionMapper.class);

    UserAuthenticator      userAuthenticator      = new UserAuthenticator(new ExternalServiceCredentialValidator(config.getAuthenticationConfiguration().getKey()));
    GroupUserAuthenticator groupUserAuthenticator = new GroupUserAuthenticator(new ServerZkAuthOperations(serverSecretParams));
    ExternalGroupCredentialGenerator externalGroupCredentialGenerator = new ExternalGroupCredentialGenerator(
        config.getGroupConfiguration().getExternalServiceSecret(), Clock.systemUTC());

    AuthFilter<BasicCredentials, User>      userAuthFilter      = new BasicCredentialAuthFilter.Builder<User>().setAuthenticator(userAuthenticator).buildAuthFilter();
    AuthFilter<BasicCredentials, GroupUser> groupUserAuthFilter = new BasicCredentialAuthFilter.Builder<GroupUser>().setAuthenticator(groupUserAuthenticator).buildAuthFilter();

    PolicySigner        policySigner        = new PolicySigner(config.getCdnConfiguration().getAccessSecret(), config.getCdnConfiguration().getRegion());
    PostPolicyGenerator postPolicyGenerator = new PostPolicyGenerator(config.getCdnConfiguration().getRegion(), config.getCdnConfiguration().getBucket(), config.getCdnConfiguration().getAccessKey());

    environment.jersey().register(new PolymorphicAuthDynamicFeature<>(ImmutableMap.of(User.class, userAuthFilter, GroupUser.class, groupUserAuthFilter)));
    environment.jersey().register(new PolymorphicAuthValueFactoryProvider.Binder<>(ImmutableSet.of(User.class, GroupUser.class)));

    environment.jersey().register(new HealthCheckController());
    environment.jersey().register(new BackupsController(backupsManager));
    environment.jersey().register(new StorageController(storageManager));
    environment.jersey().register(new GroupsController(groupsManager, serverSecretParams, policySigner, postPolicyGenerator, config.getGroupConfiguration(), externalGroupCredentialGenerator));

    environment.metrics().register(name(CpuUsageGauge.class, "cpu"), new CpuUsageGauge());
    environment.metrics().register(name(FreeMemoryGauge.class, "free_memory"), new FreeMemoryGauge());
    environment.metrics().register(name(NetworkSentGauge.class, "bytes_sent"), new NetworkSentGauge());
    environment.metrics().register(name(NetworkReceivedGauge.class, "bytes_received"), new NetworkReceivedGauge());
    environment.metrics().register(name(FileDescriptorGauge.class, "fd_count"), new FileDescriptorGauge());
  }

  public static void main(String[] argv) throws Exception {
    new StorageService().run(argv);
  }
}
