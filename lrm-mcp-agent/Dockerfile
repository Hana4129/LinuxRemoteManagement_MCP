FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY go.mod go.sum* ./
RUN go mod download 2>/dev/null || true
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o lrm-mcp-agent ./cmd/lrm-mcp-agent

FROM alpine:3.19
RUN apk add --no-cache bash coreutils procps util-linux
RUN adduser -D -s /bin/bash agent
WORKDIR /app
COPY --from=builder /app/lrm-mcp-agent .
COPY config.yml .
RUN mkdir -p /app/data && chown -R agent:agent /app
USER agent
EXPOSE 8443
ENTRYPOINT ["./lrm-mcp-agent"]
CMD ["--config", "config.yml"]
