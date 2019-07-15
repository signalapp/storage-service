version = $(error version must be set on the command line to make)
configuration_repo = ../configuration

.NOTPARALLEL:
.PHONY: help copy-config build

define HELP
	@echo "  * help: Show this message"
	@echo "  * build: Runs the maven build to build the Java and both production and staging docker images"
	@echo "  * copy-config: Copies configuration from the configuration repo into the config directory"
	@echo "                 + configuration_repo variable may be set to control where to read from"
	@echo "                   (defaults to $(configuration_repo))"

endef

config/production.yml: $(configuration_repo)/storage/production.yml
	cp "$<" "$@"

config/staging.yml: $(configuration_repo)/storage/staging.yml
	cp "$<" "$@"

config/build.properties: $(configuration_repo)/storage/build.properties
	cp "$<" "$@"

config/deploy.mk: $(configuration_repo)/storage/deploy.mk
	cp "$<" "$@"

config/app.yaml: $(configuration_repo)/storage/app.yaml
	cp "$<" "$@"

config/cron.yaml: $(configuration_repo)/storage/cron.yaml
	cp "$<" "$@"

include config/deploy.mk

help:
	@echo "This makefile defines the following targets:"
	$(HELP)
copy-config: config/production.yml config/staging.yml config/build.properties config/deploy.mk config/app.yaml config/cron.yaml
build: pom.xml Dockerfile copy-config
	@echo "Starting build for $(version)"
	mvn clean package
	@echo "Finished build for $(version)"
