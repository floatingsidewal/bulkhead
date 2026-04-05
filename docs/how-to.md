# How-To Guides

## Add a New PII Pattern

1. Choose the appropriate regional file in `src/patterns/pii/`:
   - `generic.ts` — country-agnostic patterns
   - `us.ts`, `uk.ts`, `eu.ts`, `apac.ts` — country-specific

2. Add the pattern:

```typescript
export const MY_COUNTRY_ID: PiiPattern = {
  entityType: "MY_COUNTRY_ID",
  patterns: [
    /\b[A-Z]{2}\d{6}\b/g,  // Your regex here
  ],
  validate: (match) => {
    // Optional: checksum or format validation
    return true;
  },
  contextWords: ["identity", "national id", "my country"],
  baseConfidence: "medium",
  baseScore: 0.5,
};
```

3. Export it from the regional patterns array (e.g., `EU_PATTERNS`).

4. Add tests:
   - Unit test in `test/guards/pii.guard.test.ts`
   - Adversarial tests in `test/adversarial/adversarial.test.ts`

5. Run `npm test` to verify.

## Add a New Secret Pattern

1. Open `src/patterns/secrets.ts`

2. Add the pattern:

```typescript
export const MY_SERVICE_KEY: SecretPattern = {
  secretType: "MY_SERVICE_KEY",
  patterns: [/myservice_[A-Za-z0-9]{32}/g],
  minEntropy: 3.5,  // Optional: require high randomness
};
```

3. Add it to `ALL_SECRET_PATTERNS`.

4. Add tests in `test/guards/secret.guard.test.ts`.

## Add a Custom Checksum Validator

1. Open `src/validators/checksums.ts`

2. Add your validation function:

```typescript
export function myChecksum(value: string): boolean {
  // Your validation logic
  return true;
}
```

3. Reference it from your pattern's `validate` function.

## Configure Entity Types Per Workspace

In your VS Code workspace settings (`.vscode/settings.json`):

```json
{
  "bulkhead.guards.pii.enabled": true,
  "bulkhead.guards.secret.enabled": true,
  "bulkhead.guards.injection.enabled": false
}
```

## Use Bulkhead as a Library (Outside VS Code)

Bulkhead's core is framework-agnostic. You can use the guards and engine without VS Code:

```typescript
import { GuardrailsEngine } from "./src/engine/engine";
import { PiiGuard } from "./src/guards/pii.guard";
import { SecretGuard } from "./src/guards/secret.guard";
import { InjectionGuard } from "./src/guards/injection.guard";

const engine = new GuardrailsEngine();
engine.addGuard(new PiiGuard());
engine.addGuard(new SecretGuard());
engine.addGuard(new InjectionGuard());

// Scan text
const results = await engine.analyze(inputText);
for (const result of results) {
  if (!result.passed) {
    console.log(`${result.guardName}: ${result.reason}`);
    for (const d of result.detections) {
      console.log(`  [${d.source}] ${d.entityType} at ${d.start}-${d.end}: "${d.text}" (${d.score})`);
    }
  }
}

// Get redacted text
const scanResult = await engine.scan(inputText);
if (scanResult.redactedText) {
  console.log("Redacted:", scanResult.redactedText);
}
```

## Enable the BERT Model (Layer 2)

1. Enable in VS Code settings:
   ```json
   {
     "bulkhead.cascade.modelEnabled": true,
     "bulkhead.cascade.modelId": "gravitee-io/bert-small-pii-detection"
   }
   ```

2. Run "Bulkhead: Deep Scan" from the command palette. The model downloads (~29MB) on first use and caches locally.

3. Adjust the escalation threshold if you want more/fewer items sent to LLM:
   ```json
   {
     "bulkhead.cascade.escalationThreshold": 0.75
   }
   ```
   Lower = more items confirmed by BERT alone. Higher = more items escalated to LLM.

## Train a Custom Model

See [training/README.md](../training/README.md) for the full pipeline. Summary:

```bash
cd training
pip install -r requirements.txt
python data/prepare.py                          # Download dataset
python train.py --config configs/pii-small.yaml # Fine-tune
python evaluate.py --model ../models/pii-small/pytorch  # Evaluate
python export.py --model ../models/pii-small/pytorch \
  --output ../models/pii-small/onnx --quantize int8    # Export ONNX
```

Then point Bulkhead at your custom model:
```json
{
  "bulkhead.cascade.modelId": "./models/pii-small/onnx/int8"
}
```

## Handle False Positives

If Bulkhead flags something incorrectly:

1. **Dismiss it:** Click the code action "Dismiss this warning"
2. **Raise the threshold:** Increase `bulkhead.cascade.escalationThreshold`
3. **Disable a pattern:** Use entity type filtering:
   ```typescript
   new PiiGuard({ entityTypes: ["US_SSN", "CREDIT_CARD"] }) // Only these
   ```
4. **File a bug:** Add the false positive as a test case in `test/adversarial/adversarial.test.ts` under "False Positive Resistance"
