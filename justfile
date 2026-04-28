default:
	@just --list

# Packages under test — excludes ./examples/... which are runnable demos,
# not library code, and would otherwise skew coverage with 0% entries.
test_packages := `go list ./... | grep -v '/examples/'`

test:
	go test {{test_packages}} -v

test-short:
	go test {{test_packages}} -v -short

test-coverage:
	go test {{test_packages}} -cover

test-coverage-html:
	go test {{test_packages}} -coverprofile=coverage.out
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

test-race:
	go test {{test_packages}} -race

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
