#!/bin/bash
set -euo pipefail

# Linux Agent setup script (run as root)
# Creates the dedicated user, installs the binary and config.
# With --provision it also configures the admin token hash, issues an MCP Server
# credential, registers it to the Console, then starts and verifies the agent.

USER="lrm-mcp-agent"
GROUP="lrm-mcp-agent"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/lrm-mcp-agent"
DATA_DIR="/var/lib/lrm-mcp-agent"
LOG_DIR="/var/log/lrm-mcp-agent"
CONFIG_FILE="$CONFIG_DIR/config.yml"
SERVICE="lrm-mcp-agent"

# スクリプト自身の位置から配布ディレクトリを解決する (実行CWDに依存しない)
SOURCE_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

PROVISION=0

# ファイルを カレント → スクリプトの親 → dist/<os>-<arch> の順に探す
find_source_file() {
    local candidate
    for candidate in "./$1" "$SOURCE_DIR/$1" "$SOURCE_DIR"/dist/*/"$1"; do
        if [ -f "$candidate" ]; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    return 1
}

usage() {
    cat <<'USAGE'
Usage: setup.sh [--provision] [-h|--help]

  (no option)  Agentを導入する (ユーザー/ディレクトリ/バイナリ/config/systemd unit)
  --provision  上記に加えて、管理トークンhash設定 → credential発行 → Console登録 →
               サービス起動・疎通確認 までを行う。既定は対話式で、下記の環境変数を
               与えると非対話でも実行できる。

Provision用の環境変数:
  LRM_SERVER_ID                Console側のNode/server id (必須)
  LRM_CREDENTIAL_NAME          credential名 (既定: <server id>-agent)
  LRM_CREDENTIAL_SCOPE         readonly|operator (既定: operator)
  LRM_AGENT_ADMIN_TOKEN_FILE   管理secretを格納したファイル ('-' で標準入力)
  LRM_REPLACE_ADMIN_TOKEN=1    既存と異なる admin_token_hash も置換する
  LRM_CONSOLE_URL              ConsoleのURL (例: https://console.example.jp)
  LRM_CONSOLE_AUTH_HEADER_FILE 認証ヘッダを格納したファイル (1行に1ヘッダ / 複数行可)
                               (例: Authorization: Basic ...
                                    または Cookie と X-CSRF-Token の2行)
  LRM_CONSOLE_USER             Basic認証のユーザー名 (passwordファイルと併用)
  LRM_CONSOLE_PASSWORD_FILE    Basic認証のパスワードを格納したファイル
  LRM_CONSOLE_CURL_INSECURE=1  Console接続でTLS検証をスキップする
  LRM_AGENT_HEALTH_INSECURE=1  Agent health checkでTLS検証をスキップする
  LRM_REQUIRE_REGISTRATION=1   Console登録ができない場合に異常終了する
  LRM_PENDING_REGISTRATION_FILE 未登録時のペイロード保存先
                               (既定: <CONFIG_DIR>/pending-registration.json)
  LRM_CREDENTIAL_ISSUE_BIN     credential-issue のパス (既定: 自動検出)
  LRM_NONINTERACTIVE=1         対話を行わない

secretはコマンドライン引数へ渡さず、ログにも残さない。一時ファイルは終了時に削除する。
USAGE
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --provision) PROVISION=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    esac
    shift
done

echo "=== Linux Agent Setup ==="

# Create group
if ! getent group "$GROUP" > /dev/null 2>&1; then
    groupadd --system "$GROUP"
    echo "Created group: $GROUP"
fi

# Create user
if ! id "$USER" > /dev/null 2>&1; then
    useradd --system --gid "$GROUP" --home-dir "$DATA_DIR" \
        --shell /usr/sbin/nologin --comment "Linux Agent" "$USER"
    echo "Created user: $USER"
fi

# Create directories
mkdir -p "$CONFIG_DIR" "$DATA_DIR" "$LOG_DIR"
chown "$USER:$GROUP" "$DATA_DIR" "$LOG_DIR"
chmod 700 "$DATA_DIR" "$LOG_DIR"

# Install binaries (if built)
for bin in lrm-mcp-agent credential-issue; do
    if src=$(find_source_file "$bin"); then
        cp "$src" "$INSTALL_DIR/$bin"
        chmod 755 "$INSTALL_DIR/$bin"
        echo "Installed binary to $INSTALL_DIR/$bin"
    else
        echo "WARN: $bin が見つからないため配置をスキップしました" >&2
        echo "      'make dist' (Dockerでlinux/amd64ビルド) または 'make build' を実行し、" >&2
        echo "      バイナリを $SOURCE_DIR へ置いてから再実行してください" >&2
    fi
done

# Install config (if not exists)
if [ ! -f "$CONFIG_FILE" ]; then
    if src=$(find_source_file "config.yml"); then
        cp "$src" "$CONFIG_FILE"
        echo "Installed config to $CONFIG_FILE"
    fi
fi

# Ensure config permissions are correct (always run)
if [ -f "$CONFIG_FILE" ]; then
    chmod 600 "$CONFIG_FILE"
    chown "$USER:$GROUP" "$CONFIG_FILE"
    echo "Config permissions set (user: $USER, perm: 600)"
fi

# Install systemd service
SERVICE_SRC="$SOURCE_DIR/scripts/lrm-mcp-agent.service"
if [ ! -f "$SERVICE_SRC" ] && [ -f "scripts/lrm-mcp-agent.service" ]; then
    SERVICE_SRC="scripts/lrm-mcp-agent.service"
fi
if [ -f "$SERVICE_SRC" ]; then
    cp "$SERVICE_SRC" /etc/systemd/system/lrm-mcp-agent.service
    systemctl daemon-reload
    systemctl enable lrm-mcp-agent
    echo "Installed systemd service"
fi

# --------------------------------------------------------------- provision ---
# 以降は `setup.sh --provision` で実行される provision 処理。

provision_die() {
    echo "error: $*" >&2
    exit 1
}

# 対話可能かどうか (パイプ実行や LRM_NONINTERACTIVE=1 では false)
is_interactive() {
    if [ "${LRM_NONINTERACTIVE:-0}" = "1" ]; then
        return 1
    fi
    [ -t 0 ]
}

# credential-issue の実行ファイルを解決する
find_credential_issue() {
    if [ -n "${LRM_CREDENTIAL_ISSUE_BIN:-}" ]; then
        [ -x "$LRM_CREDENTIAL_ISSUE_BIN" ] || return 1
        printf '%s' "$LRM_CREDENTIAL_ISSUE_BIN"
        return 0
    fi
    local candidate
    for candidate in "$INSTALL_DIR/credential-issue" \
        "$SOURCE_DIR/credential-issue" \
        "./credential-issue" \
        "$SOURCE_DIR"/dist/*/credential-issue; do
        if [ -x "$candidate" ]; then
            printf '%s' "$candidate"
            return 0
        fi
    done
    command -v credential-issue 2>/dev/null
}

# config.yml の agent.listen から health check 用のポートを取り出す
agent_port() {
    local line listen="" sq="'"
    line=$(grep -E '^[[:space:]]*listen:' "$CONFIG_FILE" 2>/dev/null | head -1) || true
    if [ -n "$line" ]; then
        listen="${line#*listen:}"
        listen="${listen%%#*}"
        listen="${listen//[[:space:]]/}"
        listen="${listen//\"/}"
        listen="${listen//$sq/}"
    fi
    case "$listen" in
        "") printf '%s' "8443" ;;
        *:*) printf '%s' "${listen##*:}" ;;
        *) printf '%s' "$listen" ;;
    esac
}

run_provision() {
    umask 077

    local issue_bin
    if ! issue_bin=$(find_credential_issue); then
        echo "error: credential-issue CLI が見つかりません" >&2
        echo "  探した場所:" >&2
        echo "    \$LRM_CREDENTIAL_ISSUE_BIN / $INSTALL_DIR/credential-issue" >&2
        echo "    $SOURCE_DIR/credential-issue / $SOURCE_DIR/dist/*/credential-issue / PATH" >&2

        echo "  ビルド方法 (エージェントホストが linux/amd64 の場合):" >&2
        echo "    make dist    # Dockerで linux/amd64 をビルド (Goが無い環境でも可)" >&2
        echo "    make build   # Goがある環境でネイティブビルド" >&2
        echo "  ビルドしたバイナリを $SOURCE_DIR へ置くか、LRM_CREDENTIAL_ISSUE_BIN で指定して再実行:" >&2
        echo "    sudo ./scripts/setup.sh --provision" >&2
        exit 1
    fi
    [ -f "$CONFIG_FILE" ] || provision_die "config.yml が見つかりません: $CONFIG_FILE"

    local tmpdir
    tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/lrm-provision.XXXXXX")
    # 一時ファイル (secret / 登録ペイロード) は終了時に必ず削除する
    # shellcheck disable=SC2064
    trap "rm -rf -- '$tmpdir'" EXIT

    local server_id="${LRM_SERVER_ID:-}"
    local cred_name="${LRM_CREDENTIAL_NAME:-}"
    local cred_scope="${LRM_CREDENTIAL_SCOPE:-operator}"
    local console_url="${LRM_CONSOLE_URL:-}"

    if [ -z "$server_id" ] && is_interactive; then
        read -r -p "Console側のNode ID (server_id): " server_id || server_id=""
    fi
    [ -n "$server_id" ] || provision_die "LRM_SERVER_ID が未指定です (非対話実行では環境変数で指定してください)"
    [ -n "$cred_name" ] || cred_name="${server_id}-agent"
    case "$cred_scope" in
        readonly | operator) ;;
        *) provision_die "LRM_CREDENTIAL_SCOPE は readonly か operator です: $cred_scope" ;;
    esac
    if [ -z "$console_url" ] && is_interactive; then
        read -r -p "Console URL (例: https://console.example.jp / 空Enterで登録スキップ): " console_url || console_url=""
    fi
    console_url="${console_url%/}"

    echo ""
    echo "--- 1/4: Agent管理トークン (agent.admin_token_hash) ---"
    local admin_source="${LRM_AGENT_ADMIN_TOKEN_FILE:-}"
    if [ -z "$admin_source" ] && is_interactive; then
        local input_secret=""
        printf 'Agent管理secret (失効同期に使用 / 空Enterでスキップ): ' >&2
        read -r -s input_secret || input_secret=""
        echo >&2
        if [ -n "$input_secret" ]; then
            printf '%s' "$input_secret" >"$tmpdir/admin_secret"
            chmod 600 "$tmpdir/admin_secret"
            admin_source="$tmpdir/admin_secret"
        fi
        unset input_secret
    fi

    if [ -n "$admin_source" ]; then
        local replace_opt=""
        if [ "${LRM_REPLACE_ADMIN_TOKEN:-0}" = "1" ]; then
            replace_opt="-replace-admin-token"
        fi
        # shellcheck disable=SC2086
        if ! "$issue_bin" -set-admin-token -admin-token-file "$admin_source" \
            -config "$CONFIG_FILE" $replace_opt; then
            provision_die "admin_token_hash の設定に失敗しました (既存値と異なる場合は LRM_REPLACE_ADMIN_TOKEN=1 で置換できます)"
        fi
        chown "$USER:$GROUP" "$CONFIG_FILE" 2>/dev/null || true
        chmod 600 "$CONFIG_FILE"
        echo "      Console側 config の agent.admin_token に同じsecretを設定してください" >&2
    else
        echo "WARN: 管理secretが未指定のため admin_token_hash を設定していません" >&2
        echo "      Consoleからの失効同期を使う場合は後で設定してください:" >&2
        echo "        sudo credential-issue -set-admin-token -admin-token-file <secret> -config $CONFIG_FILE" >&2
    fi

    echo ""
    echo "--- 2/4: Agent credential 発行 (config.yml へ追記) ---"
    local reg_file="$tmpdir/registration.json"
    if ! "$issue_bin" -name "$cred_name" -scope "$cred_scope" -config "$CONFIG_FILE" -apply \
        -registration-file "$reg_file" -server-id "$server_id"; then
        provision_die "credential の発行に失敗しました (token id が重複している場合は LRM_CREDENTIAL_NAME を変えてください)"
    fi
    chown "$USER:$GROUP" "$CONFIG_FILE" 2>/dev/null || true
    chmod 600 "$CONFIG_FILE"

    echo ""
    echo "--- 3/4: Console 登録 (POST /api/agent-credentials) ---"
    local registered=0
    local pending_file="${LRM_PENDING_REGISTRATION_FILE:-$CONFIG_DIR/pending-registration.json}"
    if [ -n "$console_url" ]; then
        # curl の設定ファイル (-K) を使い、認証情報やペイロードを argv に載せない
        local curl_conf="$tmpdir/curl.conf" header_line="" password=""
        {
            printf 'url = "%s/api/agent-credentials"\n' "$console_url"
            printf 'request = "POST"\n'
            printf 'header = "Content-Type: application/json"\n'
            printf 'data-binary = "@%s"\n' "$reg_file"
            printf 'output = "%s/response.json"\n' "$tmpdir"
            printf 'silent\nshow-error\n'
            if [ "${LRM_CONSOLE_CURL_INSECURE:-0}" = "1" ]; then
                printf 'insecure\n'
            fi
            if [ -n "${LRM_CONSOLE_AUTH_HEADER_FILE:-}" ]; then
                [ -r "$LRM_CONSOLE_AUTH_HEADER_FILE" ] ||
                    provision_die "LRM_CONSOLE_AUTH_HEADER_FILE が読めません: $LRM_CONSOLE_AUTH_HEADER_FILE"
                # 1行1ヘッダ (複数行可): 例 "Authorization: Basic ..." /
                # "Cookie: lrm_session=..." + "X-CSRF-Token: ..." (OIDCセッション併用時)
                while IFS= read -r header_line || [ -n "$header_line" ]; do
                    header_line=$(printf '%s' "$header_line" | tr -d '\r')
                    [ -n "$header_line" ] || continue
                    printf 'header = "%s"\n' "$(escape_curl_value "$header_line")"
                done <"$LRM_CONSOLE_AUTH_HEADER_FILE"
            elif [ -n "${LRM_CONSOLE_USER:-}" ] && [ -n "${LRM_CONSOLE_PASSWORD_FILE:-}" ]; then
                [ -r "$LRM_CONSOLE_PASSWORD_FILE" ] ||
                    provision_die "LRM_CONSOLE_PASSWORD_FILE が読めません: $LRM_CONSOLE_PASSWORD_FILE"
                password=$(tr -d '\r\n' <"$LRM_CONSOLE_PASSWORD_FILE")
                printf 'user = "%s:%s"\n' "$LRM_CONSOLE_USER" "$(escape_curl_value "$password")"
                unset password
            else
                echo "WARN: Console認証情報が未指定です。Console側で認証が無効な場合のみ続行できます" >&2
                echo "      (LRM_CONSOLE_AUTH_HEADER_FILE か LRM_CONSOLE_USER + LRM_CONSOLE_PASSWORD_FILE を指定)" >&2
            fi
        } >"$curl_conf"

        local http_code=""
        http_code=$(curl -K "$curl_conf" -w '%{http_code}' 2>"$tmpdir/curl.err") || true
        if [ "$http_code" = "200" ] || [ "$http_code" = "201" ]; then
            registered=1
            echo "      Console登録OK (HTTP $http_code)" >&2
            head -c 500 "$tmpdir/response.json" 2>/dev/null >&2 || true
            echo "" >&2
            rm -f "$reg_file"
        else
            echo "ERROR: Console登録に失敗しました (HTTP ${http_code:-接続失敗})" >&2
            head -c 500 "$tmpdir/response.json" 2>/dev/null >&2 || true
            head -c 500 "$tmpdir/curl.err" 2>/dev/null >&2 || true
            echo "" >&2
        fi
    else
        echo "WARN: LRM_CONSOLE_URL が未指定のため Console登録をスキップしました" >&2
    fi

    if [ "$registered" -eq 0 ]; then
        # config.yml には credential を反映済みのため、生トークンを含む登録用ペイロードだけを
        # 0600 で保存して再送できるようにする (Agent設定はロールバックしない)。
        install -m 600 "$reg_file" "$pending_file" 2>/dev/null || cp "$reg_file" "$pending_file"
        chmod 600 "$pending_file"
        echo "      未登録のため登録用ペイロードを保存しました (生トークンを含む / 0600):" >&2
        echo "        $pending_file" >&2
        echo "      登録後は必ず削除してください: rm -f $pending_file" >&2
        echo "      再送例: curl -sS -X POST '<CONSOLE_URL>/api/agent-credentials' \\" >&2
        echo "                -H 'Content-Type: application/json' <認証オプション> --data-binary @$pending_file" >&2
        if [ "${LRM_REQUIRE_REGISTRATION:-0}" = "1" ]; then
            provision_die "Console登録が完了していません (LRM_REQUIRE_REGISTRATION=1)"
        fi
    fi

    echo ""
    echo "--- 4/4: サービス起動と疎通確認 ---"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload 2>/dev/null || true
        if systemctl restart "$SERVICE"; then
            sleep 1
            systemctl is-active "$SERVICE" || true
        else
            echo "WARN: systemctl restart $SERVICE に失敗しました (journalctl -u $SERVICE を確認してください)" >&2
        fi
    else
        echo "WARN: systemctl が無いためサービス操作をスキップしました (コンテナ等)" >&2
    fi

    local port health_url health_code="" health_insecure=""
    port=$(agent_port)
    health_url="https://127.0.0.1:$port/v1/health"
    if [ "${LRM_AGENT_HEALTH_INSECURE:-0}" = "1" ]; then
        health_insecure="-k"
    fi
    if command -v curl >/dev/null 2>&1; then
        # shellcheck disable=SC2086
        health_code=$(curl -sS $health_insecure -o "$tmpdir/health.json" -w '%{http_code}' \
            "$health_url" 2>/dev/null) || health_code=""
        if [ "$health_code" = "200" ]; then
            echo "      health check OK ($health_url)" >&2
        else
            echo "WARN: health check が HTTP ${health_code:-接続失敗} を返しました: $health_url" >&2
        fi
    fi

    echo ""
    echo "=== Provision summary ==="
    echo "  server_id       : $server_id"
    echo "  credential name : $cred_name"
    echo "  scope           : $cred_scope"
    if [ "$registered" -eq 1 ]; then
        echo "  Console登録     : OK"
    else
        echo "  Console登録     : 未完了 (登録用ペイロード: $pending_file)"
    fi
    echo "  config.yml      : $CONFIG_FILE"
    echo "  health check    : $health_url"
}

# curl 設定ファイル (-K) に埋め込む値のエスケープ (バックスラッシュとダブルクォート)
escape_curl_value() {
    local value="$1" bs='\' dq='"'
    value="${value//$bs/$bs$bs}"
    value="${value//$dq/$bs$dq}"
    printf '%s' "$value"
}

if [ "$PROVISION" -eq 1 ]; then
    run_provision
fi

echo ""
echo "=== Setup complete ==="
echo ""
if [ "$PROVISION" -eq 1 ]; then
    echo "Provisionの結果は上記の summary を参照してください。"
    echo "Console登録が未完了の場合は、保存された登録用ペイロードをConsoleへ一度だけ提出し、"
    echo "提出後は必ず削除してください (rm -f <payload>)。"
else
    echo "Next steps:"
    echo "  1. (推奨) 失効同期用のAdmin secretを設定する:"
    echo "       printf '%s' '<admin-secret>' > /root/.lrm-admin-secret && chmod 600 /root/.lrm-admin-secret"
    echo "       sudo credential-issue -set-admin-token -admin-token-file /root/.lrm-admin-secret \\"
    echo "         -config $CONFIG_FILE"
    echo "       # 同じsecretを Console 側 config の agent.admin_token にも設定する"
    echo "  2. MCP Server用credentialを発行する (Agent側・標準フロー):"
    echo "       sudo credential-issue -name <credential-name> -scope operator -config $CONFIG_FILE \\"
    echo "         -apply -registration-file /root/registration.json -server-id <server-id>"
    echo "       # /root/registration.json (0600) をConsoleのPOST /api/agent-credentialsへ一度だけ提出し削除"
    echo "  3. 上記1〜2をまとめて行う場合: sudo ./scripts/setup.sh --provision"
    echo "  4. Start: systemctl start lrm-mcp-agent"
    echo "  5. Check status: systemctl status lrm-mcp-agent"
    echo ""
    echo "  (旧方式: sudo ./scripts/setup-tokens.sh — 対話入力によるhash設定。credential-issue を推奨)"
fi
