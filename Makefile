export GO111MODULE = on

ifneq ($(shell command -v bash),)
test test-all: SHELL := bash
test test-all: .SHELLFLAGS := -o pipefail -c
_FILTER := | grep -v "no test files"
endif

.PHONY: build clean test test-all test-cover bench fmt-changed lint

# sidescale is Linux-only (it depends on Tailscale upstream packages whose
# primary deployment target is Linux), so build/test pin GOOS=linux.
build:
	@mkdir -p bin
	GOOS=linux go build -o ./bin/sidescale ./sidescale

clean:
	rm -rf bin/

test:
	GOOS=linux go test -short ./... $(_FILTER)

test-all:
	GOOS=linux go test -race -cover ./... $(_FILTER)

test-cover:
	GOOS=linux go test -race -coverprofile=test.out ./... && go tool cover --html=test.out

bench:
	GOOS=linux go test --benchmem -benchtime=20s -bench='Benchmark.*' -run='^$$' ./...

fmt-changed:
	@files=$$( { git diff --name-only --diff-filter=d HEAD -- '*.go'; git ls-files --others --exclude-standard -- '*.go'; } | sort -u); \
	if [ -n "$$files" ]; then \
		gofmt -w $$files; \
	fi

lint: fmt-changed
	golangci-lint run --config=.golangci.yml --timeout=600s && GOOS=linux go vet ./...
