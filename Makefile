version = $(error version must be set on the command line to make)
configuration_repo = ../configuration
configuration_files = config/production.yml config/staging.yml config/build.properties config/deploy.mk config/app-production.yaml config/app-staging.yaml config/cron.yaml

.NOTPARALLEL:
.PHONY: help copy-config build

define HELP
	@echo "  * help: Show this message"
	@echo "  * build: Runs the maven build to build the Java and both production and staging docker images"
	@echo "  * copy-config: Copies configuration from the configuration repo into the config directory"
	@echo "                 + configuration_repo variable may be set to control where to read from"
	@echo "                   (defaults to $(configuration_repo))"

endef

$(configuration_files): config/%: $(configuration_repo)/storage/% | config
	cp -v "$<" "$@"

include config/deploy.mk

help:
	@echo "This makefile defines the following targets:"
	$(HELP)
config:
	mkdir -p config
copy-config: $(configuration_files)
build: pom.xml Dockerfile copy-config
	@echo "Starting build for $(version)"
	mvn clean package
	@echo "Finished build for $(version)"
