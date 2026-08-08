BINARY := stik-net
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
PREFIX ?= /usr/local

.PHONY: build test vet fmt install uninstall clean oui demo

build: ## build the stik-net binary
	go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/stik-net

test: ## run the test suite
	go test ./...

vet: ## static checks
	go vet ./...

fmt: ## format the code
	gofmt -l -w .

install: build ## install to $(PREFIX)/bin (needs write access)
	install -d $(PREFIX)/bin
	install -m 0755 $(BINARY) $(PREFIX)/bin/$(BINARY)

uninstall: ## remove the installed binary
	rm -f $(PREFIX)/bin/$(BINARY)

oui: ## regenerate the embedded IEEE OUI table
	go run ./internal/identify/ouidata/gen.go

clean:
	rm -f $(BINARY)
