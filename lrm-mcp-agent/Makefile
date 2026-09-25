.PHONY: build run test clean docker dist fmt vet

BINARY=lrm-mcp-agent
CMD=./cmd/lrm-mcp-agent
CONFIG=config.yml

build:
	go mod tidy
	go build -o $(BINARY) $(CMD)
	go build -o credential-issue ./cmd/gen-token

run: build
	./$(BINARY) --config $(CONFIG)

test:
	go test -v ./...

clean:
	rm -f $(BINARY)
	rm -f credential-issue
	rm -rf data/ dist/

docker:
	docker build -t lrm-mcp-agent:latest .

# エージェントホストへ配布する linux バイナリを Docker でビルドする (Go が無い環境でも可)。
# 既定は amd64。arm64 が必要な場合は `make dist DIST_ARCH=arm64`。
# 生成物: dist/linux-$(DIST_ARCH)/{lrm-mcp-agent,credential-issue}
# エージェントホストへ2ファイルをコピーし、setup.sh と同じディレクトリに置いて
# `sudo ./scripts/setup.sh --provision` を実行する。
DIST_ARCH ?= amd64

dist:
	mkdir -p dist/linux-$(DIST_ARCH)
	docker run --rm -v "$(CURDIR):/app" -w /app \
		-e CGO_ENABLED=0 -e GOOS=linux -e GOARCH=$(DIST_ARCH) golang:1.22 \
		sh -c 'go build -trimpath -ldflags "-s -w" -o dist/linux-$(DIST_ARCH)/$(BINARY) $(CMD) && \
		       go build -trimpath -ldflags "-s -w" -o dist/linux-$(DIST_ARCH)/credential-issue ./cmd/gen-token'
	@ls -lh dist/linux-$(DIST_ARCH)/
	@echo "エージェントホストへ dist/linux-$(DIST_ARCH)/ の2ファイルをコピーしてください"

fmt:
	gofmt -w ./

vet:
	go vet ./...
