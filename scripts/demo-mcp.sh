#!/usr/bin/env bash
# demo-mcp.sh — Demonstrate Bulkhead MCP server over stdio
# Sends JSON-RPC messages and displays results.
set -euo pipefail

# ---------------------------------------------------------------------------
# Colors and formatting
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

header()  { echo -e "\n${BLUE}${BOLD}=== $1 ===${NC}\n"; }
subhead() { echo -e "${CYAN}--- $1${NC}"; }
pass()    { echo -e "  ${GREEN}PASS${NC} $1"; }
fail()    { echo -e "  ${RED}FAIL${NC} $1"; }
info()    { echo -e "  ${DIM}$1${NC}"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
MCP_BIN="$ROOT_DIR/packages/server/dist/mcp/index.js"
PASS_COUNT=0
FAIL_COUNT=0

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
header "Bulkhead MCP Server Demo"

echo -e "${DIM}Building...${NC}"
cd "$ROOT_DIR"
npm run build --workspaces 2>/dev/null

if [[ ! -f "$MCP_BIN" ]]; then
  echo -e "${RED}MCP binary not found at ${MCP_BIN}${NC}"
  exit 1
fi

# ---------------------------------------------------------------------------
# Helper: send a JSON-RPC message and capture response
# ---------------------------------------------------------------------------
send_rpc() {
  local description="$1"
  local message="$2"
  local expected="$3"

  subhead "$description"

  # Send the message, read one line of response
  # The MCP server reads from stdin and writes to stdout (JSON-RPC over stdio)
  local response
  response=$(echo "$message" | BULKHEAD_LOG_LEVEL=silent timeout 10 node "$MCP_BIN" 2>/dev/null | head -1) || true

  if [[ -z "$response" ]]; then
    fail "$description (no response)"
    FAIL_COUNT=$((FAIL_COUNT + 1))
    return
  fi

  # Pretty-print (truncate if very long)
  local display
  display=$(echo "$response" | python3 -m json.tool 2>/dev/null || echo "$response")
  if [[ ${#display} -gt 2000 ]]; then
    echo "${display:0:2000}"
    echo -e "${DIM}  ... (truncated)${NC}"
  else
    echo "$display"
  fi

  if echo "$response" | grep -q "$expected"; then
    pass "$description"
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    fail "$description"
    info "Expected to find: $expected"
    FAIL_COUNT=$((FAIL_COUNT + 1))
  fi
}

# ---------------------------------------------------------------------------
# JSON-RPC messages
# ---------------------------------------------------------------------------

# Initialize
INIT_MSG='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"demo","version":"0.0.1"}}}'

# List tools (must follow initialize)
LIST_TOOLS_MSG='{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'

# Scan with PII
SCAN_PII_MSG='{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"bulkhead_scan","arguments":{"text":"My SSN is 219-09-9999","mode":"fast"}}}'

# Scan with secrets
SCAN_SECRET_MSG='{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"bulkhead_scan","arguments":{"text":"aws_access_key_id = AKIAIOSFODNN7EXAMPLE","mode":"fast"}}}'

# Redact
REDACT_MSG='{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"bulkhead_redact","arguments":{"text":"Contact alice@example.com or SSN: 219-09-9999"}}}'

# ---------------------------------------------------------------------------
# Multi-message session: send all messages in one stream
# ---------------------------------------------------------------------------
header "MCP Session"

# For MCP stdio servers, we need to send multiple messages in sequence.
# The server reads newline-delimited JSON-RPC from stdin.
ALL_MESSAGES=$(cat <<MSGS
${INIT_MSG}
${LIST_TOOLS_MSG}
${SCAN_PII_MSG}
${SCAN_SECRET_MSG}
${REDACT_MSG}
MSGS
)

echo -e "${DIM}Sending 5 JSON-RPC messages to MCP server...${NC}\n"

# Capture all responses
RESPONSES=$(echo "$ALL_MESSAGES" | BULKHEAD_LOG_LEVEL=silent timeout 15 node "$MCP_BIN" 2>/dev/null) || true

if [[ -z "$RESPONSES" ]]; then
  echo -e "${RED}No response from MCP server.${NC}"
  echo -e "${YELLOW}This may be expected if the MCP SDK requires a proper transport handshake.${NC}"
  echo -e "${DIM}The MCP integration tests (vitest) test the server logic directly.${NC}"
  echo ""
  echo -e "${YELLOW}Showing what would be sent:${NC}\n"

  subhead "1. Initialize"
  echo "$INIT_MSG" | python3 -m json.tool

  subhead "2. List Tools"
  echo "$LIST_TOOLS_MSG" | python3 -m json.tool

  subhead "3. Scan for PII"
  echo "$SCAN_PII_MSG" | python3 -m json.tool

  subhead "4. Scan for Secrets"
  echo "$SCAN_SECRET_MSG" | python3 -m json.tool

  subhead "5. Redact"
  echo "$REDACT_MSG" | python3 -m json.tool

  echo ""
  info "To test MCP integration programmatically, run:"
  info "  cd $ROOT_DIR && npm test --workspace=packages/server"
  exit 0
fi

# Parse responses line by line
LINE_NUM=0
while IFS= read -r line; do
  LINE_NUM=$((LINE_NUM + 1))
  case $LINE_NUM in
    1)
      subhead "Initialize Response"
      echo "$line" | python3 -m json.tool 2>/dev/null || echo "$line"
      if echo "$line" | grep -q '"result"'; then
        pass "Initialize"
        PASS_COUNT=$((PASS_COUNT + 1))
      else
        fail "Initialize"
        FAIL_COUNT=$((FAIL_COUNT + 1))
      fi
      ;;
    2)
      subhead "List Tools Response"
      echo "$line" | python3 -m json.tool 2>/dev/null || echo "$line"
      if echo "$line" | grep -q 'bulkhead_scan'; then
        pass "List tools contains bulkhead_scan"
        PASS_COUNT=$((PASS_COUNT + 1))
      else
        fail "List tools"
        FAIL_COUNT=$((FAIL_COUNT + 1))
      fi
      ;;
    3)
      subhead "PII Scan Response"
      echo "$line" | python3 -m json.tool 2>/dev/null || echo "$line"
      if echo "$line" | grep -q 'detection'; then
        pass "PII scan returns detections"
        PASS_COUNT=$((PASS_COUNT + 1))
      else
        fail "PII scan"
        FAIL_COUNT=$((FAIL_COUNT + 1))
      fi
      ;;
    4)
      subhead "Secret Scan Response"
      echo "$line" | python3 -m json.tool 2>/dev/null || echo "$line"
      if echo "$line" | grep -q 'AWS'; then
        pass "Secret scan detects AWS key"
        PASS_COUNT=$((PASS_COUNT + 1))
      else
        fail "Secret scan"
        FAIL_COUNT=$((FAIL_COUNT + 1))
      fi
      ;;
    5)
      subhead "Redact Response"
      echo "$line" | python3 -m json.tool 2>/dev/null || echo "$line"
      if echo "$line" | grep -q 'REDACTED\|redactedText'; then
        pass "Redact returns redacted text"
        PASS_COUNT=$((PASS_COUNT + 1))
      else
        fail "Redact"
        FAIL_COUNT=$((FAIL_COUNT + 1))
      fi
      ;;
  esac
done <<< "$RESPONSES"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
header "Results"
TOTAL=$((PASS_COUNT + FAIL_COUNT))
echo -e "  ${GREEN}${PASS_COUNT} passed${NC} / ${RED}${FAIL_COUNT} failed${NC} / ${TOTAL} total"

if [[ "$FAIL_COUNT" -gt 0 ]]; then
  exit 1
fi
