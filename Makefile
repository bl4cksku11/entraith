# Entraith — build & dev tasks.
# Pure-Go build (modernc sqlite), no CGO required. Go 1.24+.

BINARY   := entraith
PKG      := ./cmd/entraith
CONFIG   ?= engagement.conf
GOFLAGS  :=
LDFLAGS  := -s -w

.DEFAULT_GOAL := build

.PHONY: build
build: ## Build the binary
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY) $(PKG)

.PHONY: run
run: build ## Build and start the console with $(CONFIG)
	./$(BINARY) server --config $(CONFIG)

.PHONY: validate
validate: build ## Validate a config file without starting
	./$(BINARY) validate --config $(CONFIG)

.PHONY: test
test: ## Run the test suite
	go test ./...

.PHONY: cover
cover: ## Run tests with a coverage summary
	go test -cover ./...

.PHONY: vet
vet: ## go vet
	go vet ./...

.PHONY: tidy
tidy: ## Sync go.mod / go.sum
	go mod tidy

.PHONY: check
check: vet test ## vet + test (the CI gate)

.PHONY: docker
docker: ## Build the container image
	docker build -t $(BINARY) .

.PHONY: clean
clean: ## Remove build artifacts
	rm -f $(BINARY)

.PHONY: help
help: ## List targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
