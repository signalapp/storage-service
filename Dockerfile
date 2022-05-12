FROM eclipse-temurin:17-jre-focal

EXPOSE 8080

COPY target/lib /usr/share/signal/lib

ARG CONFIG_FILE
COPY config/${CONFIG_FILE} /usr/share/signal/config.yml

ARG JAR_FILE
COPY target/${JAR_FILE} /usr/share/signal/StorageService.jar

ENTRYPOINT ["/opt/java/openjdk/bin/java", "-server", "-Djava.awt.headless=true", "-Xmx8192m", "-Xss512k", "-XX:+HeapDumpOnOutOfMemoryError", "-jar", "/usr/share/signal/StorageService.jar", "server", "/usr/share/signal/config.yml"]
