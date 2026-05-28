# Changelog

All notable changes to this project will be documented in this file. See [VERSIONING.md](VERSIONING.md) for version numbering conventions.

## [0.5.7](https://github.com/floatingsidewal/bulkhead/compare/bulkhead-v0.5.6...bulkhead-v0.5.7) (2026-05-28)


### Features

* **engine:** add scanObject&lt;T&gt;() for structured input ([6ddaad4](https://github.com/floatingsidewal/bulkhead/commit/6ddaad44620c94d97cb4443ca4c3a80519aa4d3d))
* **engine:** synthesize mode with default registry and per-call consistency ([69c13c9](https://github.com/floatingsidewal/bulkhead/commit/69c13c96eeb53b28c86bf19d18c06ad848474c18))
* **pii:** canonical 8-4-4-4-12 hex GUID/UUID detector ([c2de2ac](https://github.com/floatingsidewal/bulkhead/commit/c2de2ac6e0aaf046400a1ea86823ed743098c950))
* **pii:** canonical 8-4-4-4-12 hex GUID/UUID detector (0.5.4) ([0462552](https://github.com/floatingsidewal/bulkhead/commit/0462552144b9d02a262f6e065f37a7f793b1ac13))
* **policy:** temporal policy modes (RFC-002) ([28b7507](https://github.com/floatingsidewal/bulkhead/commit/28b7507030eb617d9a28ac5c779305f9d0482e3c))


### Bug Fixes

* **ci:** refresh lockfile + bump cross-package deps to 0.5.4 ([ca4436c](https://github.com/floatingsidewal/bulkhead/commit/ca4436c0293c70c6aaadd6c9119f5ea094d442a9))
* correct indentation in publish-npmjs.yml ([72fdd1a](https://github.com/floatingsidewal/bulkhead/commit/72fdd1a606d182a5e013c682c9561de0ec85d545))
* **engine:** analyze() creates default RedactContext so synthesize mode works on all entry points ([3034ded](https://github.com/floatingsidewal/bulkhead/commit/3034ded2db7bd9e1e04d2b9aa31d94a8c3ca2ddd))
* produce redactedText for all guard modes and wire up testDataDetection strip ([abcfc24](https://github.com/floatingsidewal/bulkhead/commit/abcfc24d845df3c1e57ff361a60fdb2965a8cfa0))
* produce redactedText for all guard modes and wire up testDataDetection strip ([844d895](https://github.com/floatingsidewal/bulkhead/commit/844d895b0096376c13e343ed5757b5ff68cf3d61))
* proper bash conditional for provenance flag in npm publish ([6184f4e](https://github.com/floatingsidewal/bulkhead/commit/6184f4ec62e1a828b0a342e85f5fed4dff55676c))
* reference NODE_AUTH_TOKEN secret correctly in publish workflow ([e5924ce](https://github.com/floatingsidewal/bulkhead/commit/e5924ce8095d228dcd0780580fa89fcaeb062e51))

## [0.5.6] - 2026-05-04

### Changed
- chore: bump to 0.5.6 (repository recreation; omitted 0.5.5 due to npm provenance metadata mismatch after repo rip-and-replace)

## [0.5.5] - 2026-05-04 (SKIPPED)

### Note
- Repository was deleted and recreated to remove sensitive data from PR diffs. Commit hash changed; npm provenance check incompatible with 0.5.5. Version skipped; publishing resumes at 0.5.6.

## [0.5.4] - 2026-05-03

### Added
- Canonical 8-4-4-4-12 hex GUID/UUID detector in PiiGuard (score 0.7, high confidence). Closes a gap where the `synthGuid` synthesizer was registered by default but no detector emitted GUID detections.

## [0.5.3] - 2026-04-14

### Added
- Executive sales pitch section in README with regulatory exposure data, cascade mermaid diagram, and deployment summary
- New `docs/why-do-we-need-this.md` -- comprehensive business case with healthcare, fintech, enterprise SaaS, and government scenarios, architecture walkthroughs with mermaid diagrams, alternative comparison table, and cost-benefit analysis

## [0.5.2] - 2026-04-12

### Fixed
- Split bare 9-digit SSN pattern into separate low-confidence entry (baseScore 0.15) so option-set codes, status codes, and other 9-digit numbers don't false-positive as US_SSN without context words nearby

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
