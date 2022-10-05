# This overrides the default go command withenv Variables which are usually
# used in moia-dev repositories
SYSTEM                := $(shell uname -s | tr A-Z a-z)_$(shell uname -m | sed "s/x86_64/amd64/")
GO_PREFIX             := CGO_ENABLED=0 GOFLAGS=-mod=vendor
GO                    := $(GO_PREFIX) go
GOLANGCI_LINT_VERSION := 1.49.0

# Executes the linter on all our go files inside of the project
.PHONY: lint
lint: bin/golangci-lint-$(GOLANGCI_LINT_VERSION)
	$(GO_PREFIX) ./bin/golangci-lint-$(GOLANGCI_LINT_VERSION) --timeout 120s run $(LINT_TARGETS)

.PHONY: create-golint-config
create-golint-config: .golangci.yml

.golangci.yml:
	cp moia-mk-templates/assets/golangci.yml $@

# Downloads the current golangci-lint executable into the bin directory and
# makes it executable
bin/golangci-lint-$(GOLANGCI_LINT_VERSION):
	mkdir -p bin
	curl -sSLf \
		https://github.com/golangci/golangci-lint/releases/download/v$(GOLANGCI_LINT_VERSION)/golangci-lint-$(GOLANGCI_LINT_VERSION)-$(shell echo $(SYSTEM) | tr '_' '-').tar.gz \
		| tar xzOf - golangci-lint-$(GOLANGCI_LINT_VERSION)-$(shell echo $(SYSTEM) | tr '_' '-')/golangci-lint > bin/golangci-lint-$(GOLANGCI_LINT_VERSION) && chmod +x bin/golangci-lint-$(GOLANGCI_LINT_VERSION)


.PHONY: clean
clean:
	@rm -rf $(BUILD_DIR)

.PHONY: vendor
vendor:
	$(GO) mod vendor && $(GO) mod tidy

# TODO add test target once there are tests
