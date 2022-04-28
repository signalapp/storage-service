FROM amd64/ubuntu:18.04

RUN apt-get -qq update && \
    apt-get -qqy install gnupg2 locales openjdk-17-jre-headless && \
    locale-gen en_US.UTF-8 && \
    rm -rf /var/lib/apt/lists/*

ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

EXPOSE 8080

COPY target/lib /usr/share/signal/lib

ARG CONFIG_FILE
COPY config/${CONFIG_FILE} /usr/share/signal/config.yml

ARG JAR_FILE
COPY target/${JAR_FILE} /usr/share/signal/StorageService.jar

ENTRYPOINT ["/usr/bin/java", "-server", "-Djava.awt.headless=true", "-Xmx8192m", "-Xss512k", "-XX:+HeapDumpOnOutOfMemoryError", "-jar", "/usr/share/signal/StorageService.jar", "server", "/usr/share/signal/config.yml"]
