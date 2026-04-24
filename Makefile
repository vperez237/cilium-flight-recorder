.PHONY: build test clean \
	docker-build docker-up docker-down docker-logs docker-test docker-test-all docker-restart \
	helm-lint helm-template helm-install helm-upgrade helm-uninstall helm-diff \
	helm-package helm-publish

HELM_RELEASE   ?= flight-recorder
HELM_NAMESPACE ?= kube-system
HELM_VALUES    ?= helm/values-example.yaml
# Owner path under ghcr.io for chart / image publishing. Override per-fork.
OCI_REGISTRY   ?= oci://ghcr.io/vperez237/charts

# Build all binaries locally
build:
	go build -o bin/flight-recorder ./cmd/recorder
	go build -o bin/mock-cilium ./cmd/mock-cilium
	go build -o bin/mock-hubble ./cmd/mock-hubble

# Run unit tests
test:
	go test -v -race ./pkg/...

# Build Docker images
docker-build:
	docker compose build

# Start the full local environment (MinIO + mocks + flight-recorder)
docker-up: docker-build
	docker compose up -d
	@echo ""
	@echo "Services running:"
	@echo "  Flight Recorder API:  http://localhost:8080"
	@echo "  MinIO Console:        http://localhost:9001  (minioadmin/minioadmin)"
	@echo "  MinIO S3 API:         http://localhost:9000"
	@echo ""
	@echo "Useful commands:"
	@echo "  make docker-logs           # tail all logs"
	@echo "  make docker-test           # quick smoke test"
	@echo "  make docker-test-all       # full test suite (~75s)"
	@echo "  make docker-down           # stop everything"

# Stop and clean up
docker-down:
	docker compose down -v

# Restart with a fresh build (clean slate)
docker-restart:
	docker compose down -v
	docker compose build
	docker compose up -d

# Tail logs from all services
docker-logs:
	docker compose logs -f

# Quick smoke test — trigger one manual capture
docker-test:
	@echo "==> Checking health..."
	curl -s http://localhost:8080/health | jq .
	@echo ""
	@echo "==> Triggering manual capture..."
	curl -s -X POST http://localhost:8080/capture \
		-H "Content-Type: application/json" \
		-d '{"srcCIDR":"10.0.1.0/24","dstCIDR":"10.0.2.0/24","dstPort":8080,"protocol":"TCP","durationSeconds":5}' | jq .
	@echo ""
	@echo "==> Waiting 10s for capture to complete and upload..."
	sleep 10
	@echo ""
	@echo "==> Listing captures..."
	curl -s http://localhost:8080/captures | jq .

# Full test suite — exercises all features (~75 seconds)
docker-test-all:
	./scripts/test-local.sh

# --------------------------------------------------------------------------
# Helm chart targets
# --------------------------------------------------------------------------

# Lint the chart for syntax and best-practice issues
helm-lint:
	helm lint helm/ -f $(HELM_VALUES)

# Render templates locally (no cluster connection needed)
helm-template:
	helm template $(HELM_RELEASE) helm/ -n $(HELM_NAMESPACE) -f $(HELM_VALUES)

# Install or upgrade the release in the target cluster
helm-install helm-upgrade:
	helm upgrade --install $(HELM_RELEASE) helm/ \
		-n $(HELM_NAMESPACE) --create-namespace \
		-f $(HELM_VALUES)

# Show diff between the rendered chart and what's in the cluster
# (requires the helm-diff plugin: helm plugin install https://github.com/databus23/helm-diff)
helm-diff:
	helm diff upgrade $(HELM_RELEASE) helm/ \
		-n $(HELM_NAMESPACE) \
		-f $(HELM_VALUES)

# Uninstall the release
helm-uninstall:
	helm uninstall $(HELM_RELEASE) -n $(HELM_NAMESPACE)

# Package the chart into a local .tgz artifact (released versions come from
# tagged CI runs; this target is for local experimentation).
helm-package:
	helm package helm/

# Push an already-packaged chart to an OCI registry. Requires prior:
#   helm registry login ghcr.io -u <user>
# Example:
#   make helm-package && make helm-publish CHART=flight-recorder-0.1.0.tgz
CHART ?=
helm-publish:
	@if [ -z "$(CHART)" ]; then \
	  echo "CHART is required. Run 'make helm-package' first, then"; \
	  echo "  make helm-publish CHART=flight-recorder-<version>.tgz"; \
	  exit 1; \
	fi
	helm push $(CHART) $(OCI_REGISTRY)

# Remove build artifacts
clean:
	rm -rf bin/
	docker compose down -v --rmi local 2>/dev/null || true
