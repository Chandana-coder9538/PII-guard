# PII Guard

Privacy and PII masking tool in Java 21 + Spring Boot 3.
Detects Indian-context PII (Aadhaar, PAN, phone, email, IFSC, cards, IPv4, names) and applies
**MASK / HASH / TOKENIZE / REDACT** per recipe, then produces an **audit report** and a **residual scan**.

## Run it

Prerequisite: a JDK (21 or newer). **Maven is NOT needed**: the project includes the Maven Wrapper,
which downloads Maven automatically on first run.

```bash
# Easiest, any OS: Windows PowerShell/CMD:  .\run     macOS/Linux/Git Bash:  ./run.sh

# Or call the wrapper directly
# Windows (PowerShell / CMD)
.\mvnw.cmd test               # 9 unit tests
.\mvnw.cmd spring-boot:run    # starts on http://localhost:8080

# macOS / Linux
./mvnw test
./mvnw spring-boot:run
```

Open http://localhost:8080 for the UI. Data lives in `./data` (H2 file DB + masked outputs).

With PostgreSQL via Docker:

```bash
docker compose up --build
```

## Try the API

```bash
# mask text
curl -s localhost:8080/api/mask/text -H 'Content-Type: application/json' \
  -d '{"text":"mail ravi@example.com phone 9876543210 PAN ABCDE1234F"}'

# dry-run detection (returns types, offsets, fingerprints; never raw values)
curl -s localhost:8080/api/detect -H 'Content-Type: application/json' \
  -d '{"text":"call 9876543210"}'

# mask a CSV with the default recipe
curl -s -F file=@sample/customers.csv localhost:8080/api/mask/file

# job, download, audit
curl -s localhost:8080/api/jobs/<id>
curl -OJ localhost:8080/api/jobs/<id>/download
curl -s "localhost:8080/api/jobs/<id>/audit?format=csv"

# reverse a token (privileged)
curl -s localhost:8080/api/vault/detokenize -H 'X-API-Key: dev-admin-key' \
  -H 'Content-Type: application/json' -d '{"token":"TKN_AADHAAR_xxxxxxxxxxxx"}'
```

## Recipe

```json
{ "name": "vendor-share-v1", "rules": [
  { "type": "AADHAAR", "action": "TOKENIZE" },
  { "type": "PHONE",   "action": "MASK" },
  { "type": "EMAIL",   "action": "HASH" },
  { "type": "NAME",    "action": "MASK", "columns": ["customer_name"] } ] }
```

Rules with `columns` apply to those CSV columns (whole cell); rules without run regex detection on all text.

## Configuration (env vars)

| Variable | Purpose |
|---|---|
| `PIIGUARD_HMAC_SECRET` | key for HASH and fingerprints |
| `PIIGUARD_VAULT_SECRET` | passphrase for AES-256-GCM vault encryption |
| `PIIGUARD_ADMIN_KEY` | required `X-API-Key` for detokenize |
| `SPRING_DATASOURCE_URL/USERNAME/PASSWORD` | switch from H2 to PostgreSQL |
| `PIIGUARD_OUTPUT_DIR` | where masked files are written |

**Change all defaults before any real use.** Losing `PIIGUARD_VAULT_SECRET` makes tokens irreversible.

## Layout

```
detect/   regex detectors + Verhoeff (Aadhaar) and Luhn (cards) validators
action/   mask, hash (HMAC-SHA256), tokenize, redact
crypto/   Hmac, AesGcm
engine/   Recipe, RecipeEngine (detect, resolve overlaps, apply, audit, residual scan)
io/       streaming CSV and line processors
vault/    TokenVault (deterministic tokens, AES-GCM encrypted originals)
audit/    Job + AuditEvent entities (metadata only, never raw values)
api/      REST controllers
```

## Limits (be honest in your compliance docs)

- Regex finds structured PII well but **cannot reliably find free-text names or addresses**. Use column rules,
  or add an NER detector (e.g. Apache OpenNLP) behind the `Detector` interface.
- The residual scan only re-checks regex-detectable types.
- Detokenize uses a static API key. For production use Spring Security with roles.
- Audit events are saved in one batch per job; for very large files switch to chunked saves.
