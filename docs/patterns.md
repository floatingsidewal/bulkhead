# Pattern Reference

Complete list of all detection patterns in Bulkhead with their validation methods and source.

## PII Patterns (45+ entity types)

### Generic

| Entity | Score | Validation | Source |
|--------|-------|-----------|--------|
| `CREDIT_CARD` | 0.3 | Luhn checksum | Presidio |
| `EMAIL_ADDRESS` | 0.5 | TLD format | Presidio |
| `IBAN_CODE` | 0.5 | Mod-97 checksum | Presidio |
| `IP_ADDRESS` | 0.6 | IPv4/v6 format | Presidio |
| `MAC_ADDRESS` | 0.6 | Broadcast/null rejection | Presidio |
| `PHONE_NUMBER` | 0.4 | Format matching | Presidio |
| `URL` | 0.6 | Protocol detection | Presidio |
| `CRYPTO` | 0.5 | Bitcoin address format | Presidio |
| `DATE_TIME` | 0.3 | Format matching | Presidio |

### US

| Entity | Score | Validation | Source |
|--------|-------|-----------|--------|
| `US_SSN` | 0.5 | Invalid prefix/group/serial rejection | Presidio |
| `US_DRIVER_LICENSE` | 0.3 | State format matching | Presidio |
| `US_PASSPORT` | 0.1 | Format matching | Presidio |
| `US_BANK_NUMBER` | 0.05 | Context-dependent | Presidio |
| `US_ITIN` | 0.5 | Range validation | Presidio |
| `US_MBI` | 0.5 | CMS position rules | Presidio |
| `US_NPI` | 0.1 | NPI Luhn (80840 prefix) | Presidio |
| `ABA_ROUTING_NUMBER` | 0.05 | Weighted checksum [3,7,1...] | Presidio |
| `MEDICAL_LICENSE` | 0.4 | DEA modified Luhn | Presidio |

### UK

| Entity | Score | Validation | Source |
|--------|-------|-----------|--------|
| `UK_NHS` | 0.5 | Weighted sum mod 11 | Presidio |
| `UK_NINO` | 0.5 | Prefix exclusion rules | Presidio |
| `UK_PASSPORT` | 0.1 | Format matching | Presidio |
| `UK_POSTCODE` | 0.1 | Position-based letter rules | Presidio |
| `UK_VEHICLE_REGISTRATION` | 0.2 | Age ID validation | Presidio |

### EU

| Entity | Score | Validation | Source |
|--------|-------|-----------|--------|
| `ES_NIF` | 0.5 | Mod-23 letter check | Presidio |
| `ES_NIE` | 0.5 | XYZ prefix + mod-23 | Presidio |
| `IT_FISCAL_CODE` | 0.3 | Odd/even char maps + mod-26 control | Presidio |
| `IT_DRIVER_LICENSE` | 0.2 | Format matching | Presidio |
| `IT_VAT_CODE` | 0.1 | Weighted digit checksum | Presidio |
| `IT_PASSPORT` | 0.01 | Format matching | Presidio |
| `IT_IDENTITY_CARD` | 0.01 | 3 formats (paper/CIE 2.0/3.0) | Presidio |
| `PL_PESEL` | 0.4 | Weighted checksum [1,3,7,9...] | Presidio |
| `FI_PERSONAL_IDENTITY_CODE` | 0.5 | Mod-31 control char | Presidio |
| `SE_PERSONNUMMER` | 0.5 | Luhn + samordningsnummer date | Presidio |
| `DE_TAX_ID` | 0.5 | ISO 7064 Mod 11,10 | Presidio |
| `DE_PASSPORT` | 0.4 | ICAO charset validation | Presidio |

### APAC + Africa

| Entity | Score | Validation | Source |
|--------|-------|-----------|--------|
| `SG_NRIC_FIN` | 0.5 | Prefix letter validation | Presidio |
| `SG_UEN` | 0.3 | Format A/B/C weighted checksums | Presidio |
| `AU_ABN` | 0.1 | Weighted mod-89 | Presidio |
| `AU_ACN` | 0.1 | Weighted mod-10 complement | Presidio |
| `AU_TFN` | 0.1 | Weighted mod-11 | Presidio |
| `AU_MEDICARE` | 0.1 | Weighted checksum [1,3,7,9...] | Presidio |
| `IN_PAN` | 0.5 | 4th char type validation | Presidio |
| `IN_AADHAAR` | 0.01 | Verhoeff checksum + non-palindrome | Presidio |
| `IN_VEHICLE_REGISTRATION` | 0.5 | State format matching | Presidio |
| `IN_VOTER` | 0.3 | 2nd char restricted set | Presidio |
| `IN_PASSPORT` | 0.1 | Format matching | Presidio |
| `KR_RRN` | 0.5 | Region code + weighted checksum | Presidio |
| `KR_PASSPORT` | 0.1 | Prefix letter validation | Presidio |
| `TH_TNIN` | 0.5 | Province code + weighted checksum | Presidio |
| `NG_NIN` | 0.01 | Verhoeff checksum | Presidio |

## Secret Patterns (17 types)

| Type | Pattern Prefix | Entropy Check | Source |
|------|---------------|---------------|--------|
| `AWS_ACCESS_KEY` | `AKIA` | No | HAI-Guardrails |
| `AWS_SECRET_KEY` | 40 chars | Yes (≥4.5) | HAI-Guardrails |
| `GITHUB_TOKEN` | `ghp_`, `gho_`, etc. | No | HAI-Guardrails |
| `GITLAB_TOKEN` | `glpat-`, etc. | No | HAI-Guardrails |
| `AZURE_CONNECTION_STRING` | `DefaultEndpointsProtocol=` | No | Bulkhead |
| `GCP_SERVICE_ACCOUNT` | `"private_key"` | No | Bulkhead |
| `JWT_TOKEN` | `eyJ...eyJ...` | No | HAI-Guardrails |
| `PRIVATE_KEY` | `-----BEGIN...PRIVATE KEY-----` | No | HAI-Guardrails |
| `NPM_TOKEN` | `npm_` | No | Bulkhead |
| `SLACK_TOKEN` | `xox[bporas]-` | No | HAI-Guardrails |
| `STRIPE_KEY` | `sk_live_`, `rk_live_` | No | Bulkhead |
| `DATABASE_CONNECTION_STRING` | `postgres://`, etc. | No | Bulkhead |
| `SENDGRID_KEY` | `SG.` | No | Bulkhead |
| `TWILIO_KEY` | `SK` + 32 hex | No | Bulkhead |
| `OPENAI_KEY` | `sk-...T3BlbkFJ` | No | Bulkhead |
| `ANTHROPIC_KEY` | `sk-ant-` | No | Bulkhead |
| `GENERIC_SECRET` | Key=value assignment | Yes (≥3.5) | HAI-Guardrails |

## Injection Patterns (16 regex + 25 heuristic keywords)

See `src/patterns/injection.ts` for the full pattern list. Key categories:
- Instruction override ("ignore/disregard/forget previous instructions")
- Role reassignment ("you are now a", "act as if", "pretend to be")
- System manipulation ("new instructions:", "system:", "DAN mode")
- Safety bypass ("bypass safety filters", "disable safety mode")
- Temporal override ("from now on you will")

## Leakage Patterns (7 regex + 11 heuristic keywords)

See `src/patterns/injection.ts` for the full pattern list. Key categories:
- Direct extraction ("reveal/show system prompt")
- Indirect extraction ("what are your instructions")
- Reproduction requests ("repeat everything above", "copy text before")
