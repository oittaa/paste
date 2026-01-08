.PHONY: build test lint lint-go sec test-docker clean help

GO_FILES := $(shell find . -name '*.go' -not -path "./vendor/*")

help: ## Display this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-15s\033[0m %s\n", $$1, $$2}'

build: ## Build the binary
	go build -o paste .

test: ## Run unit tests
	go test -v ./...

lint: ## Run all linters (Go and JS)
	golangci-lint run
	npm run lint

lint-go: ## Run Go linter (golangci-lint)
	golangci-lint run

sec: ## Run security scan (gosec)
	gosec ./...

test-docker: ## Run E2E tests in Docker
	docker build -t paste-e2e -f Dockerfile.e2e . && docker run --rm paste-e2e

clean: ## Clean build artifacts
	rm -f paste
	rm -f results.sarif
