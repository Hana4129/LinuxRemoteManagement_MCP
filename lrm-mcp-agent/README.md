# Linux Agent (Go)

Linux Remote Management Agent - Go implementation.

## Prerequisites

- **Go 1.22 or later** must be installed.

### Installing Go on Linux

```bash
# Download (check https://go.dev/dl/ for the latest version)
wget https://go.dev/dl/go1.22.5.linux-amd64.tar.gz

# Remove any existing Go installation
sudo rm -rf /usr/local/go

# Extract to /usr/local
sudo tar -C /usr/local -xzf go1.22.5.linux-amd64.tar.gz

# Add to PATH (add to ~/.bashrc or ~/.profile for persistence)
export PATH=$PATH:/usr/local/go/bin

# Verify installation
go version
```

> If Go is installed but not found in PATH, restart your terminal or run `source ~/.bashrc`.

## Architecture

```
MCP Server ──HTTPS + Bearer Token──> Linux Agent ──Dedicated User──> OS
```

## Features

- HTTPS/TLS 1.2+ with auto-generated self-signed certificates
- Bearer Token authentication (SHA-256 hash comparison, constant-time)
- Policy-based authorization (readonly/operator scope)
- Allowlist-based access control (deny by default)
- Structured API (no shell exposure for MVP operations)
- JSON audit logging
- Rate limiting per client IP

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| GET | /v1/health | Health check |
| GET | /v1/system | System info (hostname, OS, kernel, uptime, memory) |
| GET | /v1/disk | Disk usage (df-based) |
| GET | /v1/processes | Process list (ps-based, max 100) |
| GET | /v1/services/{name} | Service status (systemctl is-active) |
| POST | /v1/services/{name}/restart | Restart service (operator scope) |
| GET | /v1/services/{name}/logs | Service logs (journalctl) |
| GET | /v1/files?path=... | Read file (allowlist + denied list) |
| POST | /v1/execute | Execute command (allowlist, operator scope) |

## Quick Start

```bash
# Build
make build

# Run (generates self-signed cert in ./data)
make run

# Health check (no auth)
curl -k https://localhost:8443/v1/health

# Test with readonly token
curl -k -H "Authorization: Bearer token1" https://localhost:8443/v1/system

# Test with operator token
curl -k -H "Authorization: Bearer token2" https://localhost:8443/v1/system
```

## Configuration

See `config.yml` for example configuration.

### Token Hash Generation

```bash
python3 -c "import hashlib; print(hashlib.sha256(b'your-raw-token').hexdigest())"
```

## Deployment

### systemd

```bash
sudo ./scripts/setup.sh
sudo ./scripts/setup-tokens.sh    # Interactive token setup
sudo systemctl start lrm-mcp-agent
```

### Docker

```bash
make docker
docker run -p 8443:8443 -v /var/lib/lrm-mcp-agent:/app/data lrm-mcp-agent:latest
```

## Security Design

- AI ≠ root (dedicated user, not root)
- Token is authentication, not authorization
- Structured API preferred over shell
- Deny by default
- Token leak assumed (defense in depth)
