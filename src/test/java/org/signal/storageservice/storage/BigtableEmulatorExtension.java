package org.signal.storageservice.storage;

import com.google.cloud.bigtable.emulator.v2.Emulator;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

/**
 * A JUnit 5 extension that manages a Bigtable {@link Emulator} instance. Modeled after
 * {@code com.google.cloud.bigtable.emulator.v2.BigtableEmulatorRule}.
 */
public class BigtableEmulatorExtension implements BeforeEachCallback, AfterEachCallback {

  private Emulator emulator;

  static BigtableEmulatorExtension create() {
    return new BigtableEmulatorExtension();
  }

  private BigtableEmulatorExtension() {

  }

  @Override
  public void beforeEach(final ExtensionContext context) throws Exception {
    emulator = Emulator.createBundled();
    emulator.start();
  }

  @Override
  public void afterEach(final ExtensionContext context) throws Exception {
    emulator.stop();
    emulator = null;
  }

  public int getPort() {
    return emulator.getPort();
  }
}
