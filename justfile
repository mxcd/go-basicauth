default:
	@just --list

test:
	go test ./... -v

test-short:
	go test ./... -v -short

test-coverage:
	go test ./... -cover

test-coverage-html:
	go test ./... -coverprofile=coverage.out
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

test-race:
	go test ./... -race

build:
	go build ./...

example:
	go run examples/simple/main.go

example-tfa:
	go run examples/tfa/main.go

clean:
	rm -f coverage.out coverage.html

fmt:
	go fmt ./...

vet:
	go vet ./...

lint:
	golangci-lint run

check: fmt vet test
	@echo "All checks passed!"
