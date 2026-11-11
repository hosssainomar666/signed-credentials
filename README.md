# signed-credentials

Issue tamper-evident credentials: HMAC-signed tokens, PDF certificates with a QR code, and a SHA-256 hash of every PDF that is stored and re-checked. Includes a command line tool, a public verification web page and API, and a token-protected admin API.

Python 3.10+, Flask, SQLite, reportlab. No other services needed. Learning prototype: issued documents carry a "demonstration document" footer.

## Quick start

```bash
python -m venv venv && source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt

python -m credentials genkey                         # prints CRED_KEYS and ADMIN_API_TOKEN lines
export CRED_KEYS=k1:<value printed above>            # keep secret, never commit
export ADMIN_API_TOKEN=<value printed above>         # only needed for the admin API

python -m credentials issue --name "Nusrat Jahan" --type membership --org "GreenGrid Ltd"
python -m credentials serve                          # http://127.0.0.1:5000
python -m unittest discover -v                       # 54 tests
```

Without `CRED_KEYS` the program refuses to start. For a quick local try-out only: `APP_ENV=development` uses a random throwaway key (tokens stop verifying after a restart).

To scan the QR code with a phone, issue and serve with your laptop's address: `BASE_URL=http://192.168.x.x:5000 python -m credentials serve --host 0.0.0.0`.

## What it does

| Feature | How |
|---|---|
| Signed tokens | `<key id>.<random id>.<signature>`. Random id = 96 random bits. Signature = first 16 bytes of HMAC-SHA256(key, domain, key id, random id), base64url. |
| Verify without the database | The signature is checked first with `hmac.compare_digest`. Forged or malformed tokens are rejected without any database query. A valid signature then goes to the database for the credential's state. |
| Key rotation | Keys have ids (`CRED_KEYS=k1:...,k2:...`, `CRED_ACTIVE_KEY=k2`). New tokens use the active key. Old tokens keep verifying until their key is removed from the list, which also acts as a way to retire a whole batch. |
| Credential types | `membership`, `noc` (No Objection Certificate), `approval` (letter of approval). NOC and approval require a purpose. |
| PDF certificate | A4 landscape with holder, type, serial, dates, key id, QR code and the printed code. Generated once at issue time. |
| Atomic issuing | Serial number, database row and PDF are one unit inside a `BEGIN IMMEDIATE` transaction. The PDF is written to a temp file and renamed. If anything fails, the transaction rolls back and no PDF or temp file is left behind. Concurrent issuers queue up and get unique serials (tested with 8 threads). |
| Integrity hash | SHA-256 of the exact PDF bytes is stored. The PDF is never regenerated. Every download recomputes the hash and refuses a changed or missing file. |
| Audit | `audit` re-hashes every stored PDF (exit code 1 on any problem). Failures are written to the `events` table. |
| Public PDF check | Upload a PDF and find out whether it is byte-for-byte one that was issued, and its current state. Limited to 2 MB, must start with `%PDF`, rate-limited. |
| Event log | Issued, verified, pdf_checked, revoked, integrity_failed. |

## Command line

```
python -m credentials genkey [--id k1]
python -m credentials issue --name NAME --type {membership,noc,approval} [--org ORG] [--purpose TEXT] [--days N] [--base-url URL]
python -m credentials verify TOKEN            # exit 0 only if valid
python -m credentials revoke SERIAL [--reason TEXT]
python -m credentials list
python -m credentials audit                   # exit 1 if any stored PDF differs
python -m credentials pdf SERIAL [--out FILE] # copies out only after the integrity check
python -m credentials check-pdf FILE          # is this file one we issued, unchanged?
python -m credentials serve [--host H] [--port P]
```

Data lives in `./data` (`credentials.db` and `issued/`), or in `CRED_DATA_DIR`.

## Web and API

Public (no login):

| Route | Purpose |
|---|---|
| `GET /` | Verify form and PDF upload |
| `GET /verify/<token>` | Result page (valid, expired, revoked, not found) |
| `GET /api/verify/<token>` | JSON result. Returns only name, organization, type, purpose, serial and dates. Never the token, hash or file path. |
| `GET /qr/<token>.png` | QR image for an existing credential |
| `POST /check-pdf`, `POST /api/check-pdf` | Upload check (field name `pdf`) |

Admin (header `Authorization: Bearer $ADMIN_API_TOKEN`; disabled when the variable is not set):

```bash
curl -X POST localhost:5000/api/credentials -H "Authorization: Bearer $ADMIN_API_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"holder_name":"Rahim Uddin","credential_type":"noc","purpose":"Tender submission","valid_days":30}'

POST /api/credentials/<serial>/revoke     {"reason": "..."}
GET  /api/credentials/<serial>/pdf        # integrity-checked download, 409 if changed or missing
GET  /api/audit
```

## Design decisions

- The QR code holds only a link. Trust lives in the server, so credentials can be revoked and a made-up QR proves nothing.
- The token's signature covers the random id and key id, so it can be checked before any database access.
- The readable serial (`CRD-2026-000001`) is never used for lookup, so it cannot be enumerated.
- Constant-time comparisons for signatures, hashes and the admin token. Token patterns use `fullmatch` so a trailing newline cannot slip through.
- Pages are sent with no-store caching so a revocation shows immediately, plus a strict Content-Security-Policy and other security headers.
- All SQL is parameterized. Template output is auto-escaped (tested with a script-tag name).

## Threat model

| Attack | Outcome |
|---|---|
| Invent or edit a token | Signature fails, rejected with no database lookup |
| Swap the key id on a valid token | Signature fails |
| Edit a PDF and pass it on | Hash differs, public check says "no match" |
| Stored PDF changed or deleted on the server | Download refused (409), event logged, `audit` fails |
| Real QR code copied onto a fake document | **Not prevented.** The page shows the true holder, so the person checking must compare the name |
| Attacker who can change both the database and the files | **Not prevented.** Keep off-server backups and ship the event log elsewhere |
| Signing key leaks | Attacker can make well-signed tokens, but they still need a matching database row. Rotate the key |
| Request flooding | Per-IP limits (in-memory, one process). Behind a proxy, configure it to pass the real client address |

HMAC proves a token came from the key holder, but third parties cannot check it offline. Verification is therefore a live lookup. The next step for offline verification would be Ed25519 public-key signatures.

## Known limits

- PDF text uses built-in fonts (Latin only); other characters print as `?`. Bangla would need a Unicode font and text shaping.
- Single process and SQLite. For real use put it behind HTTPS, use a managed secret store, and move to PostgreSQL or MySQL.
- No user accounts, email, or payment. Admin access is one shared bearer token.

## Layout

```
credentials/
  config.py     key loading and validation
  tokens.py     HMAC token create and verify
  store.py      SQLite schema and queries
  pdfgen.py     PDF and QR rendering
  service.py    issue, verify, revoke, integrity, audit
  web.py        Flask app and API
  cli.py        command line tool
  templates/    verification pages
tests/          54 unit and integration tests
```
