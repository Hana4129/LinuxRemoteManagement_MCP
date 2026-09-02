.PHONY: build run test clean docker fmt vet

BINARY=lrm-mcp-agent
CMD=./cmd/lrm-mcp-agent
CONFIG=config.yml

build:
	go mod tidy
	go build -o $(BINARY) $(CMD)

run: build
	./$(BINARY) --config $(CONFIG)

test:
	go test -v ./...

clean:
	rm -f $(BINARY)
	rm -rf data/

docker:
	docker build -t lrm-mcp-agent:latest .

fmt:
	gofmt -w ./

vet:
	go vet ./...
