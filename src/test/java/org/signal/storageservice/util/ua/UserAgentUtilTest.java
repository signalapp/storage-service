package org.signal.storageservice.util.ua;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class UserAgentUtilTest {
  @Test
  void testGetPlatformFromUserAgentString() throws UnrecognizedUserAgentException {
    String userAgentString = "Signal-Android/12.35.42 Android/31";
    ClientPlatform platform = UserAgentUtil.getPlatformFromUserAgentString(userAgentString);
    assertThat(platform).isSameAs(ClientPlatform.ANDROID);
  }

  @Test
  void testGetPlatformFromUserAgentString_null() {
    String userAgentString = null;
    assertThatThrownBy(() -> UserAgentUtil.getPlatformFromUserAgentString(userAgentString)).isInstanceOf(UnrecognizedUserAgentException.class);
  }
}
