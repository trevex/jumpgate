.DEFAULT_GOAL := help
SHELL := bash

# Extra flags passed to every `docker build`. Empty by default (portable).
# A user behind a VPN-only DNS resolver can pass DOCKER_BUILD_FLAGS=--network=host.
DOCKER_BUILD_FLAGS ?=
KIND_CLUSTER ?= jumpgate
CERT_MANAGER_VERSION ?= v1.16.2
KUBECTL_IMAGE ?= alpine/kubectl:1.34.1

ZENSICAL_IMAGE ?= zensical/zensical:latest

.PHONY: help gen sqlc build test bench lint fmt ci e2e-cluster kind-e2e web rust-deny \
        kind-images kind-up kind-down kind-redeploy kind-demo ui-e2e \
        ui-dev ui-dev-reset ui-build docs docs-serve

ui-dev: ## Start the UI dev stack (process-compose: postgres + silo + warden + vite)
	process-compose up --port 8088

ui-dev-reset: ## Wipe all local dev data (.devdata); full re-provision on next ui-dev
	rm -rf .devdata

ui-build: ## Install web deps and build the SPA (production bundle)
	pnpm --dir web install --frozen-lockfile
	pnpm --dir web build

docs: ## Build the docs site into ./site (via the zensical docker image)
	docker run --rm -v "$(CURDIR)":/docs $(ZENSICAL_IMAGE) build --clean --strict

docs-serve: ## Serve the docs with live reload at http://127.0.0.1:8000/ (Ctrl-C to stop)
	docker run --rm -it -p 127.0.0.1:8000:8000 -v "$(CURDIR)":/docs $(ZENSICAL_IMAGE) serve --dev-addr 0.0.0.0:8000

help: ## List targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*?## "} {printf "  %-12s %s\n", $$1, $$2}'

gen: ## Generate protobuf stubs (Go + Rust) and sqlc database code
	buf generate
	$(MAKE) sqlc

sqlc: ## Generate sqlc database access code (spins an ephemeral PostgreSQL)
	bash hack/gen-sqlc.sh

build: ## Build all binaries
	cd warden && go build ./...
	cd cli && go build ./...
	cargo build --workspace

test: ## Run Go + Rust tests
	cd warden && go test ./...
	cd cli && go test ./...
	cd workers/pg-proxy && go test ./...
	cargo nextest run --workspace

bench: ## Run the API/DB benchmark suite (opt-in; needs devshell postgres tooling)
	cd warden && go test -tags bench -run '^$$' -bench . -benchmem ./internal/bench/...

lint: ## Run formatters/linters
	gofmt -l warden cli 2>/dev/null | (! grep .) || (echo "gofmt needed"; exit 1)
	cd warden && golangci-lint run ./...
	cd cli && golangci-lint run ./...
	cargo fmt --all -- --check
	cargo clippy --all-targets -- -D warnings
	$(MAKE) rust-deny

rust-deny: ## Enforce the ring-only crypto invariant (ban aws-lc-rs/aws-lc-sys)
	cargo deny check bans

fmt: ## Auto-format
	gofmt -w warden cli 2>/dev/null || true
	cargo fmt --all

web: ## Install + typecheck + build the SPA
	pnpm --dir web install --frozen-lockfile
	pnpm --dir web typecheck
	pnpm --dir web build

ci: gen build test lint web ## Full CI pipeline

kind-images: ## Build the container images used by the kind env
	docker build $(DOCKER_BUILD_FLAGS) -f deploy/docker/warden.Dockerfile -t jumpgate/warden:dev .
	docker build $(DOCKER_BUILD_FLAGS) -f deploy/docker/gateway.Dockerfile -t jumpgate/gateway:dev .
	docker build $(DOCKER_BUILD_FLAGS) -f deploy/docker/ssh-proxy.Dockerfile -t jumpgate/ssh-proxy:dev .
	docker build $(DOCKER_BUILD_FLAGS) -f test/env/testworkload/sshd.Dockerfile -t jumpgate/testworkload-sshd:dev .
	docker build $(DOCKER_BUILD_FLAGS) -f test/env/testworkload/sshd-password.Dockerfile -t jumpgate/testworkload-sshd-password:dev test/env/testworkload
	docker build $(DOCKER_BUILD_FLAGS) -f test/env/testworkload/sshd-key.Dockerfile -t jumpgate/testworkload-sshd-key:dev test/env/testworkload

kind-up: ## Create the kind cluster, install cert-manager + jumpgate, deploy the ssh test workload
	kind create cluster --name $(KIND_CLUSTER) --config test/env/cluster.yaml
	kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/$(CERT_MANAGER_VERSION)/cert-manager.yaml
	kubectl -n cert-manager rollout status deploy/cert-manager --timeout=180s
	kubectl -n cert-manager rollout status deploy/cert-manager-webhook --timeout=180s
	$(MAKE) kind-images
	docker pull $(KUBECTL_IMAGE)
	kind load docker-image jumpgate/warden:dev jumpgate/gateway:dev jumpgate/ssh-proxy:dev jumpgate/testworkload-sshd:dev jumpgate/testworkload-sshd-password:dev jumpgate/testworkload-sshd-key:dev $(KUBECTL_IMAGE) --name $(KIND_CLUSTER)
	helm install jumpgate deploy/helm/jumpgate -f test/env/demo-values.yaml --wait --timeout 300s
	# The chart's bootstrap Job created Secret jumpgate-ssh-ca-pub; sshd.yaml mounts it by that name.
	kubectl apply -f test/env/testworkload/sshd.yaml
	kubectl rollout status deploy/ssh-target --timeout=120s
	kubectl apply -f test/env/testworkload/sshd-password.yaml -f test/env/testworkload/sshd-key.yaml
	kubectl rollout status deploy/ssh-target-password --timeout=120s
	kubectl rollout status deploy/ssh-target-key --timeout=120s

kind-redeploy: ## Rebuild app images, reload into the running cluster, helm upgrade + restart app pods (NOTE: cannot apply cluster.yaml changes like extraPortMappings — those need kind-down/kind-up)
	$(MAKE) kind-images
	kind load docker-image jumpgate/warden:dev jumpgate/gateway:dev jumpgate/ssh-proxy:dev --name $(KIND_CLUSTER)
	helm upgrade jumpgate deploy/helm/jumpgate -f test/env/demo-values.yaml --wait --timeout 300s
	# Images keep the :dev tag, so a manifest-only upgrade won't repull; restart to
	# pick up the freshly reloaded images.
	kubectl rollout restart deploy/jumpgate-warden deploy/jumpgate-gateway deploy/jumpgate-ssh-proxy
	kubectl rollout status deploy/jumpgate-warden --timeout=180s
	kubectl rollout status deploy/jumpgate-gateway --timeout=180s
	kubectl rollout status deploy/jumpgate-ssh-proxy --timeout=180s

kind-down: ## Delete the kind cluster
	kind delete cluster --name $(KIND_CLUSTER)

kind-demo: kind-up ## Bring up the env, export the mesh CA, build the CLI, and print setup
	kubectl get secret jumpgate-gateway-ext -o go-template='{{index .data "ca.crt" | base64decode}}' > ./jumpgate-mesh-ca.pem
	cd cli && go build -o ../jumpgate .
	@echo "warden API:  http://localhost:8080"
	@echo "gateway:     localhost:8443 (mesh CA: ./jumpgate-mesh-ca.pem)"
	@echo "admin creds: admin@demo.test / admin-password-1234"
	@echo "CLI built at ./jumpgate — it is not on PATH, so alias it: alias jumpgate=./jumpgate"
	@echo "try: jumpgate login --context admin --warden-addr http://localhost:8080"

e2e-cluster: kind-up ## Cluster-tier black-box e2e (kind + CLI); teardown after (KEEP=1 to keep up)
	cd test/e2e && JUMPGATE_E2E=1 go test -count=1 -timeout 300s ./...
	@if [ "$(KEEP)" != "1" ]; then $(MAKE) kind-down; fi

kind-e2e: e2e-cluster ## (deprecated alias)

ui-e2e: kind-up ## Bring up kind (warden serves the embedded SPA), seed Act 0 via the CLI, then run Playwright against it (KEEP=1 to keep it up)
	cd test/e2e && JUMPGATE_E2E=1 go test -run TestUISeed -count=1 -timeout 300s ./...
	pnpm --dir web install --frozen-lockfile
	pnpm --dir web exec playwright test
	@if [ "$(KEEP)" != "1" ]; then $(MAKE) kind-down; fi
