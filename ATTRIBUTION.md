# Attribution

Bulkhead draws on concepts and code from the following open-source projects:

## Microsoft Presidio
- **Repository:** https://github.com/microsoft/presidio
- **License:** MIT
- **What was used:** PII detection patterns (regex), checksum validation algorithms
  (Luhn, mod-97, etc.), context-aware confidence scoring approach, and entity type
  taxonomy covering 72+ PII types across 20+ countries.
- **Original language:** Python — patterns were ported to TypeScript

## HAI-Guardrails
- **Repository:** https://github.com/presidio-oss/hai-guardrails
- **License:** MIT
- **What was used:** Guard architecture pattern (engine → guards → tactics),
  detection tactic taxonomy (pattern, heuristic, language model), prompt injection
  and leakage detection approaches, secret detection patterns, and LLM-based
  content safety scoring patterns.
- **Original language:** TypeScript
