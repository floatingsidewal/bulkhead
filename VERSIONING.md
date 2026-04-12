# Versioning

Bulkhead uses a three-segment version number: **MAJOR.MINOR.PATCH**

## When to bump each position

| Position | Meaning | When to bump | Examples |
|----------|---------|-------------|----------|
| **PATCH** | Minor improvements | Bug fixes, pattern fixes, doc updates, CI changes, small features, config changes, dependency bumps | Heroku false positive fix, context-word scoring, README updates, new test data patterns |
| **MINOR** | Major features | Significant new capabilities that change how consumers use the project | Policy system, TestDataGuard, JSON-aware scanning, compliance policy presets |
| **MAJOR** | Breaking changes | Changes to protocol, data contract, or behavior that affect MCP tools or HTTP API | Changing MCP tool schemas, altering HTTP response shapes, removing or renaming exports that consumers depend on |

## Guidelines

- Most changes are PATCH. If you're unsure, it's probably a PATCH.
- MINOR means "consumers should read the changelog because there's a new capability they can use."
- MAJOR means "consumers' existing integrations may break and need code changes."
- Always update `CHANGELOG.md` when bumping any version.
- Bump version in all three files: `package.json`, `packages/core/package.json`, `packages/server/package.json`. Also update the server and vscode dependency on core.
