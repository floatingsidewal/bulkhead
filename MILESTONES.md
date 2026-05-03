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

## Phase 6: Sanitization & Privacy Modes

Bulkhead currently produces strong **detection** (regex + BERT + optional LLM) and basic **redaction-to-placeholder** (`[REDACTED-EMAIL_ADDRESS]`). Phase 6 extends this with **content-realistic synthesis** for downstream consumers (eval corpora, training data, demos), **temporal-policy transformations** for date/time privacy, and **structured-input handling** for callers that operate on JSON objects rather than raw strings.

The phase grew out of the support-conductor eval-corpus pipeline, which needs:
- Realistic synthetic replacements (so a sanitized triage case still reads like a real document)
- Year-zero / relative-rebased timestamps (so case content is committable to git without leaking incident dates)
- Object-shape preservation (so structured corpus YAML can be written without per-consumer recursion logic)

These are general capabilities, not project-specific.

- [ ] **6.1 RFC: Synthesize mode** *([docs/rfc-001-synthesize-mode.md](docs/rfc-001-synthesize-mode.md))*
  - Add `mode: "synthesize"` to `GuardMode` (third option alongside `block` and `redact`)
  - Per-call consistency map so `john@x.com` always maps to the same synthetic value within a document
  - Default synthesizer registry shipping for `EMAIL_ADDRESS`, `PERSON_NAME`, `PHONE_NUMBER`, `CREDIT_CARD`, `IP_ADDRESS`, `URL`, `IBAN_CODE`, `MAC_ADDRESS`, `GUID` (using IETF/RFC documentation reservations where applicable)
  - Custom synthesizers registerable via `engine.setSynthesizers()`
  - New `eval` policy preset that requests `mode: "synthesize"` for all PII guards

- [ ] **6.2 RFC: Temporal policy** *([docs/rfc-002-temporal-policy.md](docs/rfc-002-temporal-policy.md))*
  - Add `temporalPolicy?: TemporalPolicy` to `PolicyDefinition`
  - Three modes: `preserve` (current behavior), `rebase-year-zero` (replace year with `0001`, preserve month/day/time), `rebase-relative-to-earliest` (anchor all timestamps relative to a synthetic origin, preserve relative offsets)
  - Configurable precision: `ms` (default), `second`, `minute`, `hour`, `day`
  - Existing `strict` preset gains `rebase-year-zero`; `eval` preset gains `rebase-relative-to-earliest`

- [ ] **6.3 Implementation: `scanObject<T>()`** for structured input
  - New `engine.scanObject<T>(input: T): Promise<{ ...; redactedObject: T }>`
  - Recursive walker: scans every string leaf, leaves numbers/booleans/nulls/dates untouched
  - Preserves output shape exactly (object vs array, key order, nested structure)
  - Accumulates one redaction map across the whole tree for cross-leaf consistency
  - No path-matching or per-path policy in v1 — consumers handle field-level rules by pre/post-processing. Path matching can land in 6.7 if demand emerges.
  - Lowest design risk in Phase 6. Can ship in parallel with the RFCs.

- [ ] **6.4 Implementation: Synthesize mode** *(per RFC-001 after approval)*
  - Type additions, `SynthesizerRegistry` class, default synthesizers
  - `applyRedactions` mode-aware refactor in `packages/core/src/guards/base.guard.ts`
  - Engine plumbing
  - New `eval` preset
  - Tests (positive, negative, false-positive, adversarial including consistency assertions)

- [ ] **6.5 Implementation: Temporal policy** *(per RFC-002 after approval)*
  - New `applyTemporalPolicy` function in `packages/core/src/guards/temporal.ts`
  - ISO 8601 parsing and rebasing logic (UTC-normalized output)
  - Engine wiring to invoke before/alongside `applyRedactions`
  - Preset updates
  - Tests including round-trip parsing assertions and total-ordering preservation

- [ ] **6.6 Documentation: Core Engine API**
  - Document existing `engine.scan()`, `engine.modelScan()`, `engine.deepScan()`, `engine.policyScan()` in `docs/api.md` (these are public methods today but undocumented)
  - Add `engine.scanObject()`, `mode: "synthesize"`, `temporalPolicy` documentation as the implementations land
  - Update `docs/policy.md` with the new `eval` preset
  - Update `docs/guards.md` with the synthesize-mode behavior matrix

- [ ] **6.7 (Stretch): Path-aware `scanObject` policies**
  - `preservePaths: string[]` — JSON paths to skip detection entirely
  - `synthesizePaths: string[]` — JSON paths that always go through `mode: "synthesize"`
  - `hashPaths: string[]` — JSON paths whose values are replaced with a deterministic hash regardless of detection
  - Only land if 6.3 lands and consumers ask for it; v1 of `scanObject` proves out the recursion model first.
