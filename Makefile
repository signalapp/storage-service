configuration_repo = ../configuration
configuration_files = config/production.yml config/staging.yml config/staging-build.properties config/production-build.properties config/appengine-production/app.yaml config/appengine-staging/app.yaml

.NOTPARALLEL:
.PHONY: help copy-config deploy-staging deploy-production

help:
	@echo "This makefile defines the following targets:"
	@echo "  * help: Show this message"
	@echo "  * copy-config: Copies configuration from the configuration repo into the config directory"
	@echo "                 + configuration_repo variable may be set to control where to read from"
	@echo "                   (defaults to $(configuration_repo))"
	@echo "  * deploy-staging: Deploys to staging"
	@echo "  * deploy-production: Deploys to production"
config:
	mkdir -p config
	mkdir -p config/appengine-production
	mkdir -p config/appengine-staging
$(configuration_files): config/%: $(configuration_repo)/storage/% | config
	cp "$<" "$@"
copy-config: $(configuration_files)
deploy-staging: copy-config
	./mvnw clean deploy -Denv=staging appengine:deployAll@appengine
deploy-production: copy-config
	./mvnw clean deploy -Denv=production appengine:deployAll@appengine
