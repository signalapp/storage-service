# Testing

## Automated tests

The full suite of automated tests can be run using Maven from the project root:

```sh
./mvnw verify
```

## Test server

The service can be run in a feature-limited test mode by running the Maven `integration-test`
goal with the `test-server` profile activated:

```sh
./mvnw integration-test -Ptest-server [-DskipTests=true]
```

This runs [`LocalStorageService`][lss] with [test configuration][test.yml]. The application listens on port 8080, and
the admin interface on port 8081. In this mode:

- Bigtable is replaced by an in-memory [emulator][emulator] that is started on demand; all tables are created at
  startup, and data is discarded when the server stops
- storage credentials are verified with the `authentication.key` from the test configuration, and group credentials
  with `zkConfig.serverSecret`; a local [Signal Server][signal-server] configured with the matching keys can issue valid credentials

The secrets in the test configuration are for testing only and must never be used in a real deployment.

[lss]: src/test/java/org/signal/storageservice/LocalStorageService.java

[test.yml]: src/test/resources/config/test.yml

[emulator]: https://cloud.google.com/bigtable/docs/emulator

[signal-server]: https://github.com/signalapp/Signal-Server/tree/main/TESTING.md
