.PHONY: build test check bench

build:
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -o bin/vpngate ./cmd/vpngate

test:
	go test -race ./... -count=1 -timeout=90s

check:
	go vet ./...
	test -z "$$(gofmt -l cmd internal tools)"

bench:
	GOMAXPROCS=2 go test ./internal/proxy -run '^$$' -bench '^BenchmarkFetchTLS$$' -benchmem -count=3
