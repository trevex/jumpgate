.DEFAULT_GOAL := help
SHELL := bash

# Extra flags passed to every `docker build`. Empty by default (portable).
# A user behind a VPN-only DNS resolver can pass DOCKER_BUILD_FLAGS=--network=host.
DOCKER_BUILD_FLAGS ?=
KIND_CLUSTER ?= jumpgate
CERT_MANAGER_VERSION ?= v1.16.2
KUBECTL_IMAGE ?= alpine/kubectl:1.34.1

.PHONY: help gen build test lint fmt ci e2e-ssh \
        kind-images kind-up kind-down kind-demo kind-e2e

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
	cd warden && go build ./... && go build ./cmd/warden-meshcert && go build ./cmd/warden-bootstrap
	cd cli && go build ./...
	cd warden && go test -tags e2e -count=1 -timeout 300s ./e2e/...

kind-images: ## Build the four container images used by the kind env
	docker build $(DOCKER_BUILD_FLAGS) -f deploy/docker/warden.Dockerfile -t jumpgate/warden:dev .
	docker build $(DOCKER_BUILD_FLAGS) -f deploy/docker/gateway.Dockerfile -t jumpgate/gateway:dev .
	docker build $(DOCKER_BUILD_FLAGS) -f deploy/docker/ssh-proxy.Dockerfile -t jumpgate/ssh-proxy:dev .
	docker build $(DOCKER_BUILD_FLAGS) -f deploy/testworkload/sshd.Dockerfile -t jumpgate/testworkload-sshd:dev .

kind-up: ## Create the kind cluster, install cert-manager + jumpgate, deploy the ssh test workload
	kind create cluster --name $(KIND_CLUSTER) --config deploy/kind/cluster.yaml
	kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/$(CERT_MANAGER_VERSION)/cert-manager.yaml
	kubectl -n cert-manager rollout status deploy/cert-manager --timeout=180s
	kubectl -n cert-manager rollout status deploy/cert-manager-webhook --timeout=180s
	$(MAKE) kind-images
	docker pull $(KUBECTL_IMAGE)
	kind load docker-image jumpgate/warden:dev jumpgate/gateway:dev jumpgate/ssh-proxy:dev jumpgate/testworkload-sshd:dev $(KUBECTL_IMAGE) --name $(KIND_CLUSTER)
	helm install jumpgate deploy/helm/jumpgate -f deploy/kind/demo-values.yaml --wait --timeout 300s
	# The chart's bootstrap Job created Secret jumpgate-ssh-ca-pub; sshd.yaml mounts it by that name.
	kubectl apply -f deploy/testworkload/sshd.yaml
	kubectl rollout status deploy/ssh-target --timeout=120s

kind-down: ## Delete the kind cluster
	kind delete cluster --name $(KIND_CLUSTER)

kind-demo: kind-up ## Bring up the env, export the mesh CA, and print CLI setup
	kubectl get secret jumpgate-gateway-ext -o go-template='{{index .data "ca.crt" | base64decode}}' > ./jumpgate-mesh-ca.pem
	@echo "warden API:  http://localhost:8080"
	@echo "gateway:     localhost:8443 (mesh CA: ./jumpgate-mesh-ca.pem)"
	@echo "admin creds: admin@demo.test / admin-password-1234"
	@echo "try: jumpgate login --context admin --warden-addr http://localhost:8080"

kind-e2e: kind-up ## Bring up the env, run the smoke test, then tear down (KEEP=1 to keep it up)
	bash deploy/kind/smoke.sh
	@if [ "$(KEEP)" != "1" ]; then $(MAKE) kind-down; fi
