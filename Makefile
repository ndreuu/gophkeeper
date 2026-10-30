VERSION ?= dev
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
CLIENT_FLAGS = -s -w -X main.version=$(VERSION) -X main.buildDate=$(BUILD_DATE)

.PHONY: build release test vet fmt cert

build:
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -o bin/server ./cmd/server
	CGO_ENABLED=0 go build -trimpath -ldflags '$(CLIENT_FLAGS)' -o bin/gophkeeper ./cmd/client
	CGO_ENABLED=0 go build -trimpath -o bin/certgen ./cmd/certgen

release:
	mkdir -p dist
	@for target_os in linux darwin windows; do \
		for target_arch in amd64 arm64; do \
			suffix=""; if [ "$$target_os" = windows ]; then suffix=".exe"; fi; \
			CGO_ENABLED=0 GOOS=$$target_os GOARCH=$$target_arch go build -trimpath -ldflags '$(CLIENT_FLAGS)' -o dist/gophkeeper-$$target_os-$$target_arch$$suffix ./cmd/client || exit 1; \
		done; \
	done

test:
	go test -race -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out
	@go tool cover -func=coverage.out | awk '/^total:/ { if ($$3 + 0 < 70) exit 1 }'

vet:
	go vet ./...

fmt:
	gofmt -w cmd internal migrations

cert:
	go run ./cmd/certgen
