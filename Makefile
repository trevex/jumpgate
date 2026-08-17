.DEFAULT_GOAL := help
SHELL := bash

.PHONY: help gen build test lint fmt ci

help: ## List targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "} {printf "  %-12s %s\n", $$1, $$2}'

gen: ## Generate protobuf stubs (Go + Rust)
	buf generate

build: ## Build all binaries
	go build ./...
	cargo build --workspace

test: ## Run Go + Rust tests
	go test ./...
	cargo nextest run --workspace

lint: ## Run formatters/linters
	gofmt -l control-plane cli 2>/dev/null | (! grep .) || (echo "gofmt needed"; exit 1)
	golangci-lint run ./...
	cargo fmt --all -- --check
	cargo clippy --all-targets -- -D warnings

fmt: ## Auto-format
	gofmt -w control-plane cli 2>/dev/null || true
	cargo fmt --all

ci: gen build test lint ## Full CI pipeline
