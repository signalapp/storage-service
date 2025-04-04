/*
 * Copyright 2024 Signal Messenger, LLC
 * SPDX-License-Identifier: AGPL-3.0-only
 */

package org.signal.storageservice.metrics;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.doubleThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.common.net.HttpHeaders;
import io.dropwizard.core.Application;
import io.dropwizard.core.Configuration;
import io.dropwizard.core.setup.Environment;
import io.dropwizard.testing.junit5.DropwizardAppExtension;
import io.dropwizard.testing.junit5.DropwizardExtensionsSupport;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tag;
import jakarta.annotation.Priority;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.InternalServerErrorException;
import jakarta.ws.rs.NotAuthorizedException;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.PathParam;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.WebApplicationException;
import jakarta.ws.rs.client.Client;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.Response;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;
import java.util.stream.Stream;
import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.HttpChannel;
import org.eclipse.jetty.server.Request;
import org.eclipse.jetty.util.component.Container;
import org.eclipse.jetty.util.component.LifeCycle;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;

@ExtendWith(DropwizardExtensionsSupport.class)
class MetricsHttpChannelListenerIntegrationTest {

  private static final MeterRegistry METER_REGISTRY = mock(MeterRegistry.class);
  private static final Counter REQUEST_COUNTER = mock(Counter.class);
  private static final Counter RESPONSE_BYTES_COUNTER = mock(Counter.class);

  private static final AtomicReference<CountDownLatch> COUNT_DOWN_LATCH_FUTURE_REFERENCE = new AtomicReference<>();

  private static final DropwizardAppExtension<Configuration> EXTENSION =
      new DropwizardAppExtension<>(TestApplication.class);

  public static class TestApplication extends Application<Configuration> {

    @Override
    public void run(final Configuration configuration,
        final Environment environment) {

      final MetricsHttpChannelListener metricsHttpChannelListener = new MetricsHttpChannelListener(METER_REGISTRY);

      metricsHttpChannelListener.configure(environment);

      environment.lifecycle().addEventListener(new TestListener(COUNT_DOWN_LATCH_FUTURE_REFERENCE));

      environment.jersey().register(new TestResource());
      environment.jersey().register(new TestAuthFilter());
    }
  }

  @Priority(Priorities.AUTHENTICATION)
  static class TestAuthFilter implements ContainerRequestFilter {

    @Override
    public void filter(final ContainerRequestContext requestContext) {
      if (requestContext.getUriInfo().getPath().contains("unauthorized")) {
        throw new WebApplicationException(Response.Status.UNAUTHORIZED);
      }
    }
  }

  /**
   * A simple listener to signal that {@link HttpChannel.Listener} has completed its work, since its onComplete() is on
   * a different thread from the one that sends the response, creating a race condition between the listener and the
   * test assertions
   */
  static class TestListener implements HttpChannel.Listener, Container.Listener, LifeCycle.Listener {

    private final AtomicReference<CountDownLatch> completableFutureAtomicReference;

    TestListener(AtomicReference<CountDownLatch> countDownLatchReference) {
      this.completableFutureAtomicReference = countDownLatchReference;
    }

    @Override
    public void onComplete(final Request request) {
      completableFutureAtomicReference.get().countDown();
    }

    @Override
    public void beanAdded(final Container parent, final Object child) {
      if (child instanceof Connector connector) {
        connector.addBean(this);
      }
    }

    @Override
    public void beanRemoved(final Container parent, final Object child) {
    }
  }

  @Path("/v1/test")
  public static class TestResource {

    static final String GREET_FORMAT = "Hello, %s!";


    @GET
    @Path("/hello")
    public String testGetHello() {
      return "Hello!";
    }

    @GET
    @Path("/hello/{repetitions}")
    public String testGetHelloRepeated(@PathParam("repetitions") final int repetitions) {
      return "Hello!\n".repeat(repetitions);
    }

    @GET
    @Path("/greet/{name}")
    public String testGreetByName(@PathParam("name") String name) {
      if ("exception".equals(name)) {
        throw new InternalServerErrorException();
      }

      return String.format(GREET_FORMAT, name);
    }

    @GET
    @Path("/hello-async")
    public CompletionStage<String> testGetHelloAsync() {
      return CompletableFuture.completedFuture("Hello!");
    }
  }

  @AfterEach
  void teardown() {
    reset(METER_REGISTRY);
    reset(REQUEST_COUNTER);
    reset(RESPONSE_BYTES_COUNTER);
  }

  @ParameterizedTest
  @MethodSource
  @SuppressWarnings("unchecked")
  void testSimplePath(String requestPath, String expectedTagPath, String expectedResponse, int expectedStatus)
      throws Exception {

    final CountDownLatch countDownLatch = new CountDownLatch(1);
    COUNT_DOWN_LATCH_FUTURE_REFERENCE.set(countDownLatch);

    final ArgumentCaptor<Iterable<Tag>> tagCaptor = ArgumentCaptor.forClass(Iterable.class);
    when(METER_REGISTRY.counter(anyString(), any(Iterable.class)))
        .thenAnswer(invocation -> {
          final String counterName = invocation.getArgument(0);

          if (MetricsHttpChannelListener.REQUEST_COUNTER_NAME.equals(counterName)) {
            return REQUEST_COUNTER;
          } else if (MetricsHttpChannelListener.RESPONSE_BYTES_COUNTER_NAME.equals(counterName)) {
            return RESPONSE_BYTES_COUNTER;
          } else {
            return mock(Counter.class);
          }
        });

    final Client client = EXTENSION.client();

    final Supplier<String> request = () -> client.target(
            String.format("http://localhost:%d%s", EXTENSION.getLocalPort(), requestPath))
        .request()
        .header(HttpHeaders.USER_AGENT, "Signal-Android/4.53.7 (Android 8.1)")
        .get(String.class);

    final Optional<Integer> expectedContentLength;

    switch (expectedStatus) {
      case 200: {
        final String response = request.get();
        expectedContentLength = Optional.of(response.getBytes(StandardCharsets.UTF_8).length);
        assertEquals(expectedResponse, response);
        break;
      }
      case 401: {
        expectedContentLength = Optional.empty();
        assertThrows(NotAuthorizedException.class, request::get);
        break;
      }
      case 500: {
        expectedContentLength = Optional.empty();
        assertThrows(InternalServerErrorException.class, request::get);
        break;
      }
      default: {
        expectedContentLength = Optional.empty();
        fail("unexpected status");
      }
    }

    assertTrue(countDownLatch.await(1000, TimeUnit.MILLISECONDS));

    verify(METER_REGISTRY).counter(eq(MetricsHttpChannelListener.REQUEST_COUNTER_NAME), tagCaptor.capture());
    verify(REQUEST_COUNTER).increment();

    expectedContentLength.ifPresentOrElse(contentLength -> verify(RESPONSE_BYTES_COUNTER).increment(contentLength),
        () -> verify(RESPONSE_BYTES_COUNTER).increment(doubleThat(contentLength -> contentLength > 0)));

    final Iterable<Tag> tagIterable = tagCaptor.getValue();
    final Set<Tag> tags = new HashSet<>();

    for (final Tag tag : tagIterable) {
      tags.add(tag);
    }

    assertEquals(4, tags.size());
    assertTrue(tags.contains(Tag.of(MetricsHttpChannelListener.PATH_TAG, expectedTagPath)));
    assertTrue(tags.contains(Tag.of(MetricsHttpChannelListener.METHOD_TAG, "GET")));
    assertTrue(tags.contains(Tag.of(MetricsHttpChannelListener.STATUS_CODE_TAG, String.valueOf(expectedStatus))));
    assertTrue(tags.contains(Tag.of(UserAgentTagUtil.PLATFORM_TAG, "android")));
  }

  static Stream<Arguments> testSimplePath() {
    return Stream.of(
        Arguments.of("/v1/test/hello", "/v1/test/hello", "Hello!", 200),
        Arguments.of("/v1/test/hello-async", "/v1/test/hello-async", "Hello!", 200),
        Arguments.of("/v1/test/greet/friend", "/v1/test/greet/{name}",
            String.format(TestResource.GREET_FORMAT, "friend"), 200),
        Arguments.of("/v1/test/greet/unauthorized", "/v1/test/greet/{name}", null, 401),
        Arguments.of("/v1/test/greet/exception", "/v1/test/greet/{name}", null, 500),

        // This is large enough to significantly overrun the default 8 KiB buffer
        Arguments.of("/v1/test/hello/4096", "/v1/test/hello/{repetitions}", "Hello!\n".repeat(4096), 200)
    );
  }
}
