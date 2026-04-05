# Contributing to Bulkhead

Thank you for your interest in contributing to Bulkhead.

## Getting Started

```bash
git clone https://github.com/your-org/bulkhead.git
cd bulkhead
npm install
npm test        # Should pass 107 tests
npm run build   # Should produce dist/extension.js
npm run lint    # Should type-check cleanly
```

## Development Workflow

1. **Create a branch** from `main`
2. **Make your changes**
3. **Write tests** — every new pattern needs both unit and adversarial tests
4. **Run the full suite:** `npm test`
5. **Type-check:** `npm run lint`
6. **Submit a pull request**

## What to Contribute

### High-Impact Contributions

- **New PII patterns** for underrepresented countries (see `src/patterns/pii/`)
- **New secret patterns** for services not yet covered (see `src/patterns/secrets.ts`)
- **False positive fixes** — if you find a pattern that flags non-PII content, add a test case and fix the regex or add validation
- **Checksum validators** — improve detection accuracy with format validation

### Architecture Contributions

- **BERT worker improvements** — model loading optimization, caching, error handling
- **LLM layer** — provider integrations (VS Code LM API, OpenAI, Anthropic)
- **Performance** — regex compilation caching, incremental scanning

### Documentation

- **Country-specific guides** — how PII formats work in a specific country
- **Integration guides** — using Bulkhead outside VS Code

## Code Standards

### TypeScript

- Strict mode (`strict: true` in tsconfig)
- No `any` types without justification
- Interfaces over type aliases for public API types
- `readonly` on guard names and other constants

### Tests

Every pattern needs:
1. **A positive test** — detects the entity
2. **A negative test** — rejects invalid variants (bad checksums, wrong format)
3. **A false positive test** — doesn't flag similar-looking non-PII data

Add adversarial tests to `test/adversarial/adversarial.test.ts` in the appropriate section.

### Patterns

When porting from Presidio or other sources:
- **Always credit the source** in inline comments referencing `ATTRIBUTION.md`
- **Include the validation function** if the source has one (checksums, format checks)
- **Include context words** to reduce false positives
- **Set baseScore conservatively** — better to require context boost than over-flag

### Commit Messages

Use imperative mood, explain why not what:

```
Add Swedish personnummer pattern with Luhn + date validation

Ported from Microsoft Presidio's se_personnummer_recognizer.py.
Includes samordningsnummer (day+60) handling and Luhn checksum
on the 10-digit numeric portion.
```

## Project Structure

```
src/
├── types/          # Core interfaces — Detection, Guard, GuardResult
├── engine/         # GuardrailsEngine orchestrator
├── cascade/        # Cascading classifier (regex → BERT → LLM)
├── guards/         # Guard implementations
├── patterns/       # Regex patterns organized by category/region
├── validators/     # Checksum algorithms
└── vscode/         # VS Code extension integration

training/           # Python training pipeline (independent)
test/               # Test suites
docs/               # Documentation
```

## Attribution

If you port patterns from another project, update `ATTRIBUTION.md` with:
- Repository URL
- License
- What was used
- Original language

This isn't just about license compliance — it's about respecting the work others have done.

## Questions?

Open an issue. There are no stupid questions.
