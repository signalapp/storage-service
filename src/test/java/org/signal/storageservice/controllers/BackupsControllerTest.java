/*
 * Copyright 2020 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.controllers;

import com.google.cloud.bigtable.admin.v2.models.Backup;
import io.dropwizard.testing.junit.ResourceTestRule;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.signal.storageservice.storage.BackupsManager;

import javax.ws.rs.core.Response;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

public class BackupsControllerTest {
  private static final String CRON_HEADER = "X-Appengine-Cron";

  private final BackupsManager backupsManager = mock(BackupsManager.class);

  @Rule
  public final ResourceTestRule resources = ResourceTestRule.builder()
                                                            .addResource(new BackupsController(backupsManager))
                                                            .build();

  @Before
  public void setup() {
    reset(backupsManager);
  }

  @Test
  public void testNonCronCall() {
    Response response = resources.getJerseyTest()
                                 .target("/backup")
                                 .request()
                                 .get();

    assertEquals(404, response.getStatus());
    verifyNoMoreInteractions(backupsManager);
  }

  @Test
  public void testBadCronHeader() {
    Response response = resources.getJerseyTest()
                                 .target("/backup")
                                 .request()
                                 .header(CRON_HEADER, "chewbacca")
                                 .get();

    assertEquals(404, response.getStatus());
    verifyNoMoreInteractions(backupsManager);
  }

  @Test
  public void testQuickBackup() {
    CompletableFuture<Map<String, Backup>> future = CompletableFuture.completedFuture(null);
    when(backupsManager.createBackups()).thenReturn(future);

    Response response = resources.getJerseyTest()
                                 .target("/backup")
                                 .request()
                                 .header(CRON_HEADER, "true")
                                 .get();

    assertEquals(200, response.getStatus());
    verify(backupsManager).createBackups();
  }

  @Test
  public void testSlowBackup() {
    CompletableFuture<Map<String, Backup>> future = new CompletableFuture<>();
    when(backupsManager.createBackups()).thenReturn(future);

    Response response = resources.getJerseyTest()
                                 .target("/backup")
                                 .request()
                                 .header(CRON_HEADER, "true")
                                 .get();

    assertEquals(202, response.getStatus());
    verify(backupsManager).createBackups();
  }

  @Test
  public void testExceptionalBackup() {
    CompletableFuture<Map<String, Backup>> future = new CompletableFuture<>();
    future.completeExceptionally(new RuntimeException("something bad"));
    when(backupsManager.createBackups()).thenReturn(future);

    Response response = resources.getJerseyTest()
                                 .target("/backup")
                                 .request()
                                 .header(CRON_HEADER, "true")
                                 .get();

    assertEquals(500, response.getStatus());
    verify(backupsManager).createBackups();
    verifyNoMoreInteractions(backupsManager);
  }
}
