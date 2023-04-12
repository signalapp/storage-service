configuration_repo = ../configuration
configuration_files = config/production.yml config/staging.yml config/build.properties config/appengine-production/app.yaml config/appengine-production/cron.yaml config/appengine-staging/app.yaml config/appengine-staging/cron.yaml

.NOTPARALLEL:
.PHONY: help copy-config deploy-staging deploy

help:
	@echo "This makefile defines the following targets:"
	@echo "  * help: Show this message"
	@echo "  * copy-config: Copies configuration from the configuration repo into the config directory"
	@echo "                 + configuration_repo variable may be set to control where to read from"
	@echo "                   (defaults to $(configuration_repo))"
	@echo "  * deploy-staging: Deploys to staging"
	@echo "  * deploy: Deploys to staging and production"
config:
	mkdir -p config
	mkdir -p config/appengine-production
	mkdir -p config/appengine-staging
$(configuration_files): config/%: $(configuration_repo)/storage/% | config
	cp "$<" "$@"
copy-config: $(configuration_files)
deploy-staging: copy-config
	./mvnw clean deploy
deploy: copy-config
	./mvnw clean deploy appengine:deployAll@production
