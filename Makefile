.DEFAULT_GOAL := help
SHELL := bash

.PHONY: help gen build test lint fmt ci e2e-ssh

help: ## List targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "} {printf "  %-12s %s\n", $$1, $$2}'

gen: ## Generate protobuf stubs (Go + Rust)
	buf generate

build: ## Build all binaries
	cd warden && go build ./...
	cd cli && go build ./...
	cargo build --workspace

test: ## Run Go + Rust tests
	cd warden && go test ./...
	cd cli && go test ./...
	cargo nextest run --workspace

lint: ## Run formatters/linters
	gofmt -l warden cli 2>/dev/null | (! grep .) || (echo "gofmt needed"; exit 1)
	cd warden && golangci-lint run ./...
	cd cli && golangci-lint run ./...
	cargo fmt --all -- --check
	cargo clippy --all-targets -- -D warnings

fmt: ## Auto-format
	gofmt -w warden cli 2>/dev/null || true
	cargo fmt --all

ci: gen build test lint ## Full CI pipeline

e2e-ssh: ## Opt-in full-stack SSH connect e2e (real warden+gateway+worker binaries; NOT in ci)
	cargo build --workspace
	cd warden && go build ./... && go build ./cmd/warden-meshcert
	cd cli && go build ./...
	cd warden && go test -tags e2e -count=1 -timeout 300s ./e2e/...
