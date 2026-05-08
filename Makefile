.PHONY: test build run-meter run-token run-gateway run-ledger e2e negative lint-shell

test:
	go test ./...

build:
	go build ./...

run-meter:
	go run ./services/meter

run-token:
	go run ./services/token-service

run-gateway:
	go run ./services/enforcement-gateway

run-ledger:
	go run ./services/receipt-ledger


lint-shell:
	bash -n scripts/kronyx-e2e.sh
	bash -n scripts/kronyx-negative.sh

e2e:
	./scripts/kronyx-e2e.sh

negative:
	./scripts/kronyx-negative.sh
