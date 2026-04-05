# Bulkhead Milestones

## Phase 1: Bug Fixes

- [x] **1.1 API key authentication for scan/redact endpoints**
  - Add `X-API-Key` header auth for `/v1/scan`, `/v1/scan/deep`, `/v1/scan/model`, `/v1/redact`
  - Enabled when `BULKHEAD_API_KEY` env var is set; open by default
  - Health/readiness/info endpoints remain unauthenticated
  - Return 401 `{"error": "Unauthorized"}` on missing/invalid key

- [x] **1.2 MCP tool output: human-readable cascade summary**
  - Add formatted summary to `bulkhead_scan` and `bulkhead_redact` responses
  - Each detection shows: `entityType (source → disposition, score)`
  - Summary appears before the raw JSON detail

- [x] **1.3 MCP scan tool: surface cascade layer activity**
  - In `deep` mode: show layer breakdown (Layer 1: N confirmed, Layer 2: N confirmed + N escalated, etc.)
  - In `fast` mode: note "regex only — use mode: deep for full cascade"
  - Add `layerSummary` field to response

- [x] **1.4 Test performance summary with ASCII bar chart**
  - After test run, display Min/Mean/Max timing table for each guard (pii, secret, injection, leakage)
  - Include cascade total and secret pattern category breakdown
  - ASCII bar chart at bottom for visual performance comparison
  - Part of standard `npm test` output

## Phase 2: Documentation

- [x] **2.1 Update README.md**
  - Reflect monorepo structure (packages/core, packages/vscode, packages/server)
  - Document all deployment modes: VS Code extension, HTTP REST, MCP, Docker
  - Add quick-start for each mode
  - Update pattern count (154 secret types, 13 categories)

- [x] **2.2 Update docs/architecture.md**
  - Add server and MCP architecture sections
  - Document container deployment architecture
  - Update cascade diagram to show all entry points

- [x] **2.3 Deployment guide: docs/deployment.md**
  - Scenario 1: VS Code extension (local dev)
  - Scenario 2: HTTP REST server (standalone / sidecar)
  - Scenario 3: MCP server (AI assistant integration)
  - Scenario 4: Docker container (HTTP mode)
  - Scenario 5: Docker container (MCP mode)
  - Each scenario: use case, config, startup command, example requests, expected output

- [x] **2.4 API reference: docs/api.md**
  - All HTTP endpoints with request/response schemas
  - MCP tool definitions with parameter schemas
  - Environment variable reference
  - Authentication configuration

## Phase 3: Tests & Demos

- [x] **3.1 HTTP REST server integration tests**
  - Health/readiness endpoints
  - PII scan, secret scan, injection scan
  - Redact endpoint
  - Auth: open mode, API key valid, API key invalid/missing
  - Request size limits

- [x] **3.2 MCP server integration tests**
  - Initialize + list tools
  - bulkhead_scan (fast, model, deep modes)
  - bulkhead_redact
  - bulkhead_configure
  - Verify human-readable summary in output

- [x] **3.3 Docker smoke tests**
  - Build image
  - HTTP mode: health check, scan endpoint
  - MCP mode: initialize + scan
  - Security: non-root user, read-only filesystem
  - Can run as shell script or in CI

- [x] **3.4 Demo scripts**
  - `scripts/demo-http.sh` — starts server, runs sample requests, shows output
  - `scripts/demo-mcp.sh` — pipes MCP messages, shows tool responses
  - `scripts/demo-docker.sh` — builds image, runs both modes
  - Each script is self-contained and can be used for live demos

## Phase 4: CI Pipeline

- [x] **4.1 GitHub Actions: PR validation**
  - Trigger on PR to `main` and `develop`
  - Lint (tsc --noEmit for core, vscode, server)
  - Unit tests (vitest)
  - Build core + server packages
  - Docker build (no push)

- [x] **4.2 GitHub Actions: main branch**
  - All PR checks plus:
  - Integration tests (HTTP server + MCP server)
  - Docker smoke tests
  - Performance regression check (compare timing to baseline)

- [x] **4.3 Branch protection rules**
  - Document recommended branch protection for `main`
  - Require PR reviews, status checks, up-to-date branch

## Phase 5: Inference Workloads

- [x] **5.1 BERT model integration for container**
  - Pre-download model in Docker build (optional layer)
  - Model caching strategy across container restarts
  - Readiness probe gates on model load status
  - Document model size, memory requirements, cold start time

- [x] **5.2 LLM provider configuration**
  - OpenAI, Anthropic, custom endpoint providers (already built)
  - Document API key management in container (env vars, secrets)
  - Rate limiting and error handling for LLM calls
  - Cost estimation guidance per scan volume

- [x] **5.3 Deep scan end-to-end testing**
  - Test full cascade: regex → BERT → LLM with real model
  - Measure latency per layer
  - Verify escalation logic (BERT uncertain → LLM resolves)
  - Test with adversarial inputs that require LLM disambiguation

- [x] **5.4 Performance benchmarks**
  - Baseline: regex-only scan throughput (requests/sec)
  - BERT layer: latency per request, memory footprint
  - Full cascade: end-to-end latency distribution
  - Scaling: concurrent request handling in container
