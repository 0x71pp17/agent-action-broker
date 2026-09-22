.PHONY: fmt vet test lint bench fuzz eval

fmt:
	gofmt -w .

vet:
	go vet ./...

test:
	go test -race -cover ./...

lint:
	@test -z "$$(gofmt -l .)" || (echo "gofmt needed:"; gofmt -l .; exit 1)
	go vet ./...
	@command -v golangci-lint >/dev/null 2>&1 && golangci-lint run || echo "golangci-lint not installed; ran gofmt + vet only"

sec:
	@command -v gosec >/dev/null 2>&1 && gosec ./... || echo "gosec not installed; skipping"

.PHONY: sec

bench:
	go test -run '^$$' -bench . -benchmem ./...

fuzz:
	go test -run '^$$' -fuzz FuzzDecide -fuzztime 30s ./broker

eval:
	go run ./cmd/adeval
