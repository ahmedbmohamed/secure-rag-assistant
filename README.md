# Secure RAG Assistant

[![CI](https://github.com/ahmedbmohamed/secure-rag-assistant/actions/workflows/ci.yml/badge.svg)](https://github.com/ahmedbmohamed/secure-rag-assistant/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.13-blue)
![LangChain](https://img.shields.io/badge/LangChain-1.6-1C3C3C)
![pgvector](https://img.shields.io/badge/PostgreSQL-pgvector-336791)

A question answering assistant for security consultants. It answers from **OWASP Top 10:2025**, **NIST SP 800-53** and a client's **internal policies in PDF, Word, Excel or Markdown**, gives a source for every statement, and is built so that client data stays under control:

* **Local by default.** The LLM (Ollama) and the embeddings run on the client's own machine or network. Nothing is sent to a third-party AI service.
* **Access control inside the search.** A document reserved to the security team is never retrieved for other users, so it can never reach the prompt.
* **Prompt injection defense** on questions and on documents. A poisoned document is quarantined at ingestion.
* **Grounded answers.** Every statement must cite a source. Invented citations are removed, and an answer without a source is not shown.
* **Fail closed.** If the local LLM is down, the request is refused. It is never rerouted to another provider.
* **Sign-in with MFA.** Password plus a 6-digit authenticator code, HttpOnly session cookie, account lockout after 5 failures, and an administration page for accounts and roles.
* **Integrity and audit.** A signed manifest detects a modified index at startup, and every request is written to a hash-chained audit log for the SIEM.

The threat model is in [SECURITY.md](SECURITY.md).

## Architecture

```mermaid
flowchart LR
    U[User] -->|password + MFA| UI[Web interface<br/>HTML, CSS, JavaScript]
    UI -->|session cookie| API[FastAPI<br/>sessions, lockout,<br/>rate limit]
    subgraph backend [Internal network, no internet access]
        API --> G1{Injection<br/>check}
        G1 -- blocked --> LOG[(Audit log)]
        G1 -- ok --> R[Hybrid search<br/>vector + keywords<br/>filtered by role]
        R --> DB[(PostgreSQL<br/>pgvector)]
        R --> T{Relevant<br/>enough?}
        T -- no --> REF[Refuse]
        T -- yes --> LLM[Local LLM<br/>Ollama]
        LLM --> C{Valid<br/>citations?}
        C -- yes --> A[Answer + sources]
        C -- no --> REF
    end
    API --> LOG
    LOG --> SIEM[SIEM / Wazuh]
```

Ingestion runs once, before the service starts:

```mermaid
flowchart LR
    D[OWASP, NIST,<br/>PDF, Word, Excel,<br/>Markdown] --> P[Text extraction<br/>size and zip-bomb limits]
    P --> S[Chunking<br/>LangChain splitters]
    S --> Q{Injection<br/>scan}
    Q -- flagged --> X[Quarantine<br/>whole document]
    Q -- clean --> E[Embeddings<br/>bge-small, local]
    E --> DB[(pgvector)]
    E --> M[Signed manifest<br/>SHA-256 + HMAC]
```

## How it works

**Documents.** Internal files can be Markdown, PDF, Word (.docx) or Excel (.xlsx). Word headings and numbered PDF titles become sections, Word and Excel tables become one line per row with each value labelled by its column ("Vendor: Vendor 1 | Risk level: High"), so a row read alone stays clear. Who may read a file is set in [`data/internal/access.json`](data/internal/access.json). A file nobody labelled is visible to the security team only (deny by default). Files are untrusted input: size, page count, rows and the uncompressed size of Office files are capped, and files that cannot be read (encrypted or scanned PDF, unsupported format) are listed in the ingestion report and on the administration page instead of failing silently.

**Retrieval.** Documents are split by heading, then into chunks of about 900 characters with LangChain text splitters. Each chunk keeps its title and section. Search combines vector similarity (pgvector, HNSW index with iterative scan, so the role filter never shortens the results) with PostgreSQL full-text search and merges both rankings with reciprocal rank fusion. Exact terms such as "AC-2" or "SQL injection" are found by the keyword side, paraphrases by the vector side.

**Access control.** Each document carries roles (`public`, `staff`, `security-admin`). The role filter is part of the SQL query, so filtering happens before ranking and before the LLM. In the demo, `user1` (staff) cannot retrieve the incident runbook, `user2` (security-admin) can.

**Grounding.** The LLM receives the top 5 chunks as numbered sources and a system prompt that tells it to answer only from them, to cite them as `[S1]`, and to treat them as data, not instructions. The answer is then checked: citations to sources that do not exist are removed, an answer without any valid citation is refused, and an off-topic question is refused before the LLM is called when no chunk is similar enough.

**Prompt injection.** Rules in English and French detect attempts to override instructions, change role, leak the system prompt or exfiltrate documents, including payloads hidden in base64 or in HTML comments. The demo contains a vendor note with a hidden instruction. It is quarantined at ingestion and never indexed.

**Accounts and sign-in.** People sign in with a password (PBKDF2-SHA256, 600,000 iterations, 14 characters minimum) and a TOTP code from Google or Microsoft Authenticator, set up by scanning a QR code at the first sign-in. The session lives in an `HttpOnly`, `Secure`, `SameSite=Strict` cookie that JavaScript cannot read, expires after 30 minutes of inactivity or 8 hours, and gets a new token after sign-in. Five failed attempts lock the account for 15 minutes, and an address with 20 failures is blocked, for passwords and API keys alike. Each code works once. The `admin` role manages accounts (create, disable, unlock, reset MFA, change roles) but reads no documents: administration and data access are separate. Scripts use service accounts with an API key and cannot sign in to the web page.

**Cloud mode (opt-in).** If a client accepts a hosted LLM, `SRAG_LLM_MODE=cloud` must be confirmed with `SRAG_ALLOW_CLOUD=true`. Emails, phone numbers, IBANs, card numbers and IP addresses are then replaced by placeholders such as `<EMAIL_1>` before sending, and restored locally in the answer. In local mode, the service refuses to start if the LLM address is not on the machine or the private network.

## Web interface

A single page in plain HTML, CSS and JavaScript, served by the API itself (no framework, no build step, no external script).

* Sign-in and MFA setup with a QR code
* Session dashboard: questions asked, answered with sources, refused, attacks blocked, average time
* Answers with clickable citations: `[S1]` opens and highlights the matching source, with its similarity and a link to the original
* A 👍 / 👎 on every answer, so the quality can be followed in production
* The documents the signed-in user is allowed to search, with their format and a filter
* For administrators: accounts, roles, MFA status, locked accounts, recent security events, feedback totals and files that could not be indexed

Because the model output and the document text are untrusted, the page never inserts them as HTML (only as text), and the API sends a strict Content Security Policy: scripts and styles only from the API itself, no inline scripts, no framing. Requests with a session cookie from another site are refused.

## Results

Measured in CI on every push (`eval/run_eval.py`, gates in [`eval/gates.json`](eval/gates.json)) with the real embedding model:

| Metric | Result | Gate |
|---|---|---|
| Expected document among the 5 sources given to the LLM (hit@5) | **96.6%** (57 of 59 questions) | at least 85% |
| Mean reciprocal rank (MRR@5) | **0.929** | at least 0.70 |
| Off-topic questions refused before calling the LLM | **91.7%** (11 of 12) | at least 80% |
| Real questions wrongly refused | **0%** | at most 5% |
| Prompt injection detection, precision and recall | **100% / 100%** (20 attacks, 25 normal questions) | at least 95% / 90% |

The 59 questions include questions answered by the PDF, Word and Excel files. The injection set was written while building the rules, so 100% says the known patterns are covered, not that every new attack is caught. That is why injection detection is only one of the layers.

End-to-end, with the local LLM (`qwen2.5:3b` on a 4-core CPU, no GPU), on 20 questions:

| Check | Result |
|---|---|
| Questions answered with sources | **95%** (19 of 20) |
| Answers citing an expected document | **90%** of questions (18 of 20), **94.7%** of the answered ones |
| Off-topic questions refused | **6 of 6** |
| Injection attempts blocked | **6 of 6** |
| Restricted runbook shown to a user without the role | **never** |
| Median time per answer | **19 s** |

The unanswered question was asked in French, which the English embedding model handles poorly (see Limitations).

Full results: [reports/eval.json](reports/eval.json) and [reports/e2e.json](reports/e2e.json).

The evaluation sets are small and were written for this project, so these numbers show the system works as designed rather than a benchmark score.

## Screenshots

| Sign-in, then MFA set up with an authenticator app | Answer from a PDF, with the exact section |
|---|---|
| ![MFA setup](docs/mfa_setup.png) | ![PDF answer](docs/pdf_answer.png) |
| **Access control**: `user1` asks for the restricted runbook | **Prompt injection** blocked before the LLM |
| ![Access control](docs/access_control.png) | ![Injection blocked](docs/injection_blocked.png) |
| **Internal runbook** answered for a security-admin | **Administration**: accounts, MFA status, security events |
| ![Answer](docs/answer.png) | ![Administration](docs/admin.png) |

Screenshots from the end-to-end workflow, with `qwen2.5:3b` running locally on the CI machine. The workflow signs in each account and sets up its MFA like a person would.

## Run it

Requirements: Docker, about 4 GB of free disk space and 8 GB of RAM.

```bash
git clone https://github.com/ahmedbmohamed/secure-rag-assistant.git
cd secure-rag-assistant
cp .env.example .env        # then change the two secrets
make setup                  # build, download the model, index, create accounts (prints the passwords)
make up                     # http://localhost:8000
```

`make setup` is the only step with internet access: it downloads the LLM once. The running services are on an internal network.

At the first sign-in, each account scans a QR code with an authenticator app (Google Authenticator, Microsoft Authenticator…) and types the 6-digit code. The demo accounts are `admin` (account management only), `user1` (staff) and `user2` (staff and security-admin).

Without Docker, for development:

```bash
pip install -r requirements-dev.txt && pip install -e .
pytest                                  # pgvector tests need SRAG_TEST_DATABASE_URL
ollama pull qwen2.5:3b                  # https://ollama.com
python scripts/create_users.py          # prints the passwords and the service API keys
uvicorn api.main:app                    # http://localhost:8000, in-memory index when SRAG_DATABASE_URL is not set
```

Ask with the API, from a script, with a service account key:

```bash
curl -X POST http://localhost:8000/ask -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -d '{"question": "How do I prevent SQL injection?"}'
```

## Deployment and recovery

* Add or replace documents in `data/internal/`, set their roles in `access.json`, then run the ingestion again. `python scripts/make_sample_docs.py` shows how the demo PDF, Word and Excel files were made.
* Check the audit log has not been edited: `python -m srag.audit logs/audit.jsonl`.
* Everything runs in containers, so the service can be redeployed on another server with the same `docker compose` commands.
* The index is not a source of truth. It is rebuilt from the documents with `python -m srag.ingest.pipeline`. Back up the documents, the manifest and the secrets.
* Containers run as a non-root user, with a read-only file system, no Linux capabilities and `no-new-privileges`.
* For high availability, run two API instances behind a load balancer and a replicated PostgreSQL.

## CI pipeline

1. Lint and format checks (ruff)
2. Unit and API tests, including sign-in, MFA, lockout, administration, file parsing, and access control and search on a real PostgreSQL with pgvector
3. **Quality gate**: retrieval, refusal and injection detection must stay above the thresholds in `eval/gates.json`
4. Docker build and **Trivy** scan (fails on fixable critical vulnerabilities)
5. Smoke test of the container: authentication, an answer with sources, a blocked injection, a refused sign-in, the security headers and the audit chain

A separate workflow runs the whole stack with the real local LLM, measures the answers and captures the screenshots.

## Project structure

```
src/srag/
  config.py        settings, local-only check of the LLM address
  ingest/          loaders (OWASP, NIST OSCAL, Markdown, PDF, Word, Excel), chunking, ingestion pipeline
  embeddings.py    local embeddings (fastembed, ONNX)
  store.py         hybrid search, pgvector and in-memory, role filter
  guards/          prompt injection detection, PII masking
  llm.py           LangChain chat models (Ollama, OpenAI-compatible), fail closed
  rag.py           the question answering pipeline and the answer checks
  integrity.py     signed manifest
  auth.py          accounts, password hashing, sessions, lockout, rate limit, API keys
  totp.py          authenticator codes (RFC 6238) and QR code
  audit.py         hash-chained JSON audit log and its verifier
api/main.py        REST API, serves the web interface
web/               web interface (plain HTML, CSS and JavaScript, no framework)
eval/              evaluation sets and scripts
deploy/wazuh/      SIEM rules for the audit log
```

## Limitations

* Sessions, lockouts and rate limits live in the memory of one API process. Several replicas need a shared store such as Redis.
* Accounts are in a JSON file. A large company would connect the sign-in to its directory (Microsoft Entra ID or Active Directory through OpenID Connect) instead.
* Authenticator secrets are stored in the account file, protected by file permissions only. Production should encrypt them with a key from a secret manager.
* Roles apply to a whole document, not to a section of it.
* Scanned PDFs need OCR, which is not included. They are reported, not indexed.
* Questions are answered one at a time: there is no conversation memory, and the answer appears once it is complete.
* Prompt injection detection is rule based. It stops common attacks but not every new phrasing, which is why it is one layer among several.
* PII masking covers structured data (emails, phones, IBAN, cards, IP), not personal names.
* The embedding model is English. Questions in French work for the keyword part of the search but retrieval is weaker. A multilingual model would fix it at a higher cost.
* A 3B model on CPU takes several seconds per answer. A GPU or a larger model improves speed and quality.

## Data

OWASP Top 10:2025 (CC BY 3.0), NIST SP 800-53 Rev. 5 (public domain) and fictional internal documents of an invented bank. Details in [data/SOURCES.md](data/SOURCES.md).

## Author

Ahmed Benmohamed, engineer in security of computer systems and networks (TEK-UP University, 2026).
[LinkedIn](https://www.linkedin.com/in/ahmed-benmohamed-71b243309) · [GitHub](https://github.com/ahmedbmohamed)
