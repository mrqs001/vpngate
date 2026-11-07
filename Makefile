.PHONY: build test test-native check bench bench-load

build:
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -o bin/vpngate ./cmd/vpngate

test:
	go test -race ./... -count=1 -timeout=90s

test-native:
	VPNGATE_NATIVE_TEST=1 go test -race ./internal/daemon -run TestNativeNetworkIsolation -v -count=1 -timeout=90s

check:
	go vet ./...
	test -z "$$(gofmt -l cmd internal tools)"

bench:
	GOMAXPROCS=2 go test ./internal/proxy -run '^$$' -bench '^BenchmarkFetchTLS$$' -benchmem -count=3

bench-load:
	GOMAXPROCS=4 go test ./internal/proxy -run '^$$' -bench '^BenchmarkFetchSchedulerLoad$$' -benchtime=1x -v -timeout=20m
