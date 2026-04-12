# Changelog

All notable changes to this project will be documented in this file. See [VERSIONING.md](VERSIONING.md) for version numbering conventions.

## [0.5.1] - 2026-04-12

### Added
- Sentinel-year date detection in TestDataGuard: dates with year < 1900 or > 2100 flagged as `TEST_DATA_DATE`
- Use `0001-04-12T16:29:43Z` style dates in eval data to mark them as synthetic while keeping them parseable

## [0.5.0] - 2026-04-12

### Fixed
- Remove bare UUID regex from HEROKU_API_KEY pattern that matched all GUIDs as Heroku keys

### Changed
- Documentation overhaul: all install paths lead with `@bulkhead-ai/*` scope
- Comprehensive how-to.md with medical record scanning and bulk data redaction scenarios
- Fixed empty code blocks and stale version references across docs
- Updated test counts and BERT model ID references

## [0.4.0] - 2026-04-12

### Added
- Trusted publishing (OIDC) for npmjs.org -- no PAT or token needed
- On-demand npmjs.org publish workflow (`publish-npmjs.yml`)
- Packages published to both `@bulkhead-ai/*` (npmjs.org) and `@floatingsidewal/*` (GitHub Packages)
- GitHub Actions v5 for checkout/setup-node

### Changed
- Package names: `@floatingsidewal/bulkhead-core` and `@floatingsidewal/bulkhead-server` (GitHub Packages primary)
- `publishConfig.access: "public"` in package.json

## [0.3.0] - 2026-04-12

### Added
- Policy-based scanning with `strict` and `moderate` presets
- Risk assessment engine (`RiskAssessment` with level, score, classified issues)
- TestDataGuard for detecting synthetic GUIDs, test credit cards, placeholder emails, test SSNs
- `policyScan()` method on GuardrailsEngine
- `SecretGuard` gains `secretTypes` filtering (parity with PiiGuard `entityTypes`)
- `"informational"` disposition type for test data detections
- Policy composition via `resolvePolicy()`

### Fixed
- `bert-worker.ts` now builds into `dist/` (was missing, BERT broken for npm consumers)
- `bert-layer.ts` worker path updated for compiled output
- Server dependency on core changed from exact to caret range
- CI: build core before server lint/test
- CI: Docker whoami check uses `--entrypoint`
- BERT integration tests skip in CI (need model download + native bindings)

### Changed
- Root package renamed from `bulkhead-monorepo` to `bulkhead`
- Moved cascade internals to `@bulkhead-ai/core/cascade` sub-export
- `@huggingface/transformers` moved from `optionalDependencies` to `peerDependencies`

## [0.2.0] - 2026-04-12

### Added
- npm metadata (repository, homepage, bugs, keywords, engines) to both packages
- README.md for `@bulkhead-ai/core` and `@bulkhead-ai/server`
- GitHub Packages publishing via CI
- Docker image auto-push to `ghcr.io/floatingsidewal/bulkhead`
- `.gitignore` for `.DS_Store`, `.npmrc`, IDE files

## [0.1.0] - 2026-04-05

### Added
- Three-layer cascading classifier (regex, BERT, LLM)
- 45+ PII entity types across 20+ countries
- 154 secret patterns across 13 categories
- Prompt injection and system prompt leakage detection
- VS Code extension with auto-scan and code actions
- HTTP REST server (Fastify) with auth
- MCP server with scan, redact, configure tools
- Docker multi-stage build with non-root user
- BERT worker thread integration
- Adversarial test suite
- Performance benchmarks
