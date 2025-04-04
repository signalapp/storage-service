package org.signal.storageservice.configuration;

import jakarta.validation.constraints.Positive;

public record WarmupConfiguration(
    // the number of times warmup logic should run
    @Positive Integer count
) { }
