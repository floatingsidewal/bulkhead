# Changelog

## [0.9.0](https://github.com/floatingsidewal/bulkhead/compare/bulkhead-core-v0.7.0...bulkhead-core-v0.9.0) (2026-07-27)

### Features

* add async `sanitizeDocument()` for JSON-compatible keys and values
* share replacement consistency and one temporal anchor across a document
* support strict ISO, `yyyy-mm-dd`, and localized date treatment with fail-safe fallback
* arbitrate cross-guard overlaps before mutation and conservatively redact unsafe unions
* return separate pre-treatment detection and post-treatment residual-safety metadata
* preserve document shape and entries with collision-safe sanitized keys

### Compatibility

* Existing engine scan APIs remain supported.
* Localized date ambiguity defaults to `reject-ambiguous`.
* Detected invalid, short-year, or unparseable dates default to `[REDACTED-DATE_TIME]`.

## [0.6.0](https://github.com/floatingsidewal/bulkhead/compare/bulkhead-core-v0.5.6...bulkhead-core-v0.6.0) (2026-05-28)


### Features

* **engine:** add scanObject&lt;T&gt;() for structured input ([6ddaad4](https://github.com/floatingsidewal/bulkhead/commit/6ddaad44620c94d97cb4443ca4c3a80519aa4d3d))
* **engine:** synthesize mode with default registry and per-call consistency ([69c13c9](https://github.com/floatingsidewal/bulkhead/commit/69c13c96eeb53b28c86bf19d18c06ad848474c18))
* **pii:** canonical 8-4-4-4-12 hex GUID/UUID detector ([c2de2ac](https://github.com/floatingsidewal/bulkhead/commit/c2de2ac6e0aaf046400a1ea86823ed743098c950))
* **pii:** canonical 8-4-4-4-12 hex GUID/UUID detector (0.5.4) ([0462552](https://github.com/floatingsidewal/bulkhead/commit/0462552144b9d02a262f6e065f37a7f793b1ac13))
* **policy:** temporal policy modes (RFC-002) ([28b7507](https://github.com/floatingsidewal/bulkhead/commit/28b7507030eb617d9a28ac5c779305f9d0482e3c))


### Bug Fixes

* **engine:** analyze() creates default RedactContext so synthesize mode works on all entry points ([3034ded](https://github.com/floatingsidewal/bulkhead/commit/3034ded2db7bd9e1e04d2b9aa31d94a8c3ca2ddd))
* produce redactedText for all guard modes and wire up testDataDetection strip ([abcfc24](https://github.com/floatingsidewal/bulkhead/commit/abcfc24d845df3c1e57ff361a60fdb2965a8cfa0))
* produce redactedText for all guard modes and wire up testDataDetection strip ([844d895](https://github.com/floatingsidewal/bulkhead/commit/844d895b0096376c13e343ed5757b5ff68cf3d61))
