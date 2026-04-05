# Attribution

Bulkhead derives code and design from the following open-source projects.
Both are MIT-licensed. Verbatim copyright notices and license text are
reproduced in [NOTICES](NOTICES) as required by the MIT License.

## Microsoft Presidio

- **Repository:** https://github.com/microsoft/presidio
- **License:** MIT
- **Copyright:** Copyright (c) Microsoft Corporation. All rights reserved.
- **What was derived:**
  - PII detection regex patterns covering 45+ entity types across 20+ countries
    (all files under `src/patterns/pii/`)
  - Checksum validation algorithms: Luhn, IBAN mod-97, ABA weighted checksum,
    NPI Luhn, DEA modified Luhn, Verhoeff, UK NHS mod-11, Polish PESEL weighted
    checksum, Finnish mod-31, Swedish Luhn, German ISO 7064 mod-11,10,
    Italian fiscal code odd/even maps, Spanish NIF/NIE mod-23, Singapore UEN
    weighted checksums, Australian ABN/ACN/TFN/Medicare checksums, Korean RRN
    weighted checksum, Thai TNIN weighted checksum
    (`src/validators/checksums.ts`, `src/validators/verhoeff.ts`)
  - Context-aware confidence scoring approach (context words within +/-100 chars
    boost base scores by 0.35)
  - Entity type taxonomy and naming conventions
- **Original language:** Python -- patterns and algorithms were ported to TypeScript
- **Scope of derivation:** The detection patterns and checksum algorithms are
  substantially ported. The cascading classifier architecture, BERT integration,
  LLM disambiguation layer, VS Code extension, and deduplication logic are
  independently developed and not derived from Presidio.

## HAI-Guardrails

- **Repository:** https://github.com/presidio-oss/hai-guardrails
- **License:** MIT
- **Copyright:** Copyright (c) 2025 Presidio, Inc. and affiliates.
- **What was derived:**
  - Guard architecture pattern: engine orchestrates multiple guards, each guard
    applies one or more detection tactics (`src/engine/engine.ts`,
    `src/guards/base.guard.ts`)
  - Detection tactic taxonomy: pattern (regex), heuristic (string similarity),
    language model
  - Prompt injection detection approach and keyword phrases
    (`src/guards/injection.guard.ts`, `src/patterns/injection.ts`)
  - System prompt leakage detection approach and keyword phrases
    (`src/guards/leakage.guard.ts`)
  - Secret detection patterns for AWS, GitHub, GitLab, JWT, private keys,
    Slack, and generic high-entropy secrets (`src/patterns/secrets.ts`)
- **Original language:** TypeScript
- **Scope of derivation:** The guard/tactic architecture and several secret
  detection patterns are derived. The cascading classifier, BERT worker thread
  integration, LLM disambiguation layer, VS Code extension, and content safety
  scoring are independently developed and not derived from HAI-Guardrails.
