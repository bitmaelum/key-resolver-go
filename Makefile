# @echo off
.SILENT:

# Default repository
REPO="github.com/bitmaelum/key-resolver-go"

# Set environment variables from GO env if not set explicitly already
ifndef $(GOPATH)
    GOPATH=$(shell go env GOPATH)
    export GOPATH
endif
ifndef $(GOOS)
    GOOS=$(shell go env GOOS)
    export GOOS
endif
ifndef $(GOARCH)
    GOARCH=$(shell go env GOARCH)
    export GOARCH
endif

# paths to binaries
GO_STATCHECK_BIN = $(GOPATH)/bin/staticcheck
GO_INEFF_BIN = $(GOPATH)/bin/ineffassign
GO_GOCYCLO_BIN = $(GOPATH)/bin/gocyclo
GO_GOIMPORTS_BIN = $(GOPATH)/bin/goimports

# ---------------------------------------------------------------------------

# Downloads external tools as it's not available by default
$(GO_TEST_BIN):
	go get -u honnef.co/go/tools/cmd/staticcheck
	go get -u github.com/gordonklaus/ineffassign
	go get -u github.com/fzipp/gocyclo
	go get -u golang.org/x/tools/cmd/goimports


lint:
	$(GO_GOIMPORTS_BIN) -w  --format-only .

## Runs all tests for the whole repository
test: $(GO_TEST_BIN) test_goimports test_vet test_staticcheck test_ineffassign test_gocyclo test_unit

test_goimports:
	echo "goimports"
	$(GO_GOIMPORTS_BIN) -l .

test_vet:
	echo "Check vet"
	go vet ./...

test_staticcheck:
	echo "Check static"
	$(GO_STATCHECK_BIN) ./...

test_ineffassign:
	echo "Check ineffassign"
	$(GO_INEFF_BIN) ./*

test_gocyclo:
	echo "Check gocyclo"
	$(GO_GOCYCLO_BIN) -over 15 .

test_unit:
	echo "Check unit tests"
	go test ./...

clean: ## Clean releases
	go clean

# Build default OS/ARCH apps in root release directory
build-key-resolver:
	$(info -   Building app $@)
	go build $(LD_FLAGS) .

info:
	$(info Building BitMaelum key resolver)

build: info build-key-resolver

all: test build ## Run tests and build default platform binaries

help: ## Display available commands
	echo "BitMaelum make commands"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'