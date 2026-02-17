.PHONY: build clean run test

# Version information
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
GO_VERSION ?= $(shell go version | awk '{print $$3}')

# Build flags
LDFLAGS := -ldflags "-X main.version=$(VERSION) \
	-X main.gitCommit=$(GIT_COMMIT) \
	-X main.buildTime=$(BUILD_TIME) \
	-X main.goVersion=$(GO_VERSION)"

# Binary name
BINARY := gin-doh

# Build the binary
build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/server

# Build for multiple platforms
build-all:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY)-linux-amd64 ./cmd/server
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BINARY)-linux-arm64 ./cmd/server
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY)-darwin-amd64 ./cmd/server
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o $(BINARY)-darwin-arm64 ./cmd/server
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY)-windows-amd64.exe ./cmd/server

# Clean build artifacts
clean:
	rm -f $(BINARY) $(BINARY)-*

# Run the server
run: build
	./$(BINARY)

# Run tests
test:
	go test -v ./...

# Install dependencies
deps:
	go mod download
	go mod tidy

# Show version info
version:
	@echo "Version:    $(VERSION)"
	@echo "Git Commit: $(GIT_COMMIT)"
	@echo "Build Time: $(BUILD_TIME)"
	@echo "Go Version: $(GO_VERSION)"
