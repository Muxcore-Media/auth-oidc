.PHONY: build test lint clean fmt tidy docker ci help

GO ?= go
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "0.0.0-dev")
LDFLAGS ?= -s -w -X main.version=$(VERSION)
BINARY ?= auth-oidc

build:
	$(GO) build -ldflags="$(LDFLAGS)" -o $(BINARY) ./cmd/module

test:
	$(GO) test -count=1 -timeout 5m ./...

lint:
	golangci-lint run --timeout 120s ./...

clean:
	rm -f $(BINARY)
	rm -f cmd/module/module
	rm -rf dist/

fmt:
	gofmt -w .

tidy:
	$(GO) mod tidy

docker:
	docker build -f Dockerfile -t ghcr.io/muxcore-media/$(BINARY):$(VERSION) ..
	docker tag ghcr.io/muxcore-media/$(BINARY):$(VERSION) ghcr.io/muxcore-media/$(BINARY):latest

ci: lint test build

help:
	@echo "Targets:"
	@echo "  build  - compile the module binary"
	@echo "  test   - run unit tests (no -race; Fake IdP + soft-fail)"
	@echo "  lint   - golangci-lint"
	@echo "  clean  - remove build artifacts"
	@echo "  fmt    - gofmt"
	@echo "  tidy   - go mod tidy"
	@echo "  docker - build Docker image"
	@echo "  ci     - lint + test + build"
