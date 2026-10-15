# Security design and threat model

The assistant answers questions from documents that can be confidential. The design goal is simple: **a document must only reach people allowed to read it, and data must not leave the network unless someone decided it explicitly.**

## Assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| Internal documents and their chunks | PostgreSQL (pgvector) | Confidential client content |
| Questions asked by users | API memory, audit log (masked) | Can contain personal or sensitive data |
| The LLM and its weights | Ollama volume | A replaced model can give wrong or malicious answers |
| API keys | `config/users.json` (SHA-256 hashes only) | Identity and access rights |
| Manifest key | Environment variable | Protects the integrity check |

## Threats and controls

| # | Threat | Control in this project | Remaining risk |
|---|---|---|---|
| T1 | A user reads a document reserved to another role | Role filter inside the SQL query, before ranking. A chunk outside the user's roles never reaches the prompt. Tested for both stores. | Roles are only as good as the labels given at ingestion |
| T2 | Prompt injection in the question ("ignore your instructions...") | Detection in English and French, including base64-encoded payloads, before retrieval. Blocked questions are logged. | Heuristics miss new phrasings. The next layers still apply. |
| T3 | Indirect prompt injection hidden in a document | Every chunk is scanned at ingestion. One flagged chunk quarantines the whole document. The system prompt says sources are data, not instructions. | A subtle injection can pass the scanner |
| T4 | The model invents facts or sources | Answers must cite the sources given. Invented citations are removed. An answer without a valid citation is not shown. Off-topic questions are refused before the LLM. | A cited source can still be paraphrased wrongly. Users are asked to check the source (link shown). |
| T5 | The model reveals the system prompt | Output filter on prompt fingerprints | Partial paraphrases may pass |
| T6 | Data sent to a third-party AI service | Local mode by default. Startup fails if the LLM endpoint is a public address. Cloud mode needs `SRAG_ALLOW_CLOUD=true` and always masks emails, phones, IBANs, card numbers and IP addresses first. | Masking covers structured data, not names or free-text secrets |
| T7 | LLM outage pushes requests to another provider | Fail closed: HTTP 503, no fallback, event logged | Availability depends on the local LLM |
| T8 | The LLM host is compromised and exfiltrates data | The LLM and the database sit on an internal Docker network with no route to the internet. Containers run as non-root with a read-only file system, no capabilities and `no-new-privileges`. | An attacker with root on the host can still read the volumes. Disk encryption (LUKS) and host hardening are needed in production. |
| T9 | Index or model tampered with | HMAC-signed manifest of every document hash, checked at startup. The service refuses to start with a database and a default or short manifest key. Optional pinned model digest checked against Ollama. Any difference stops the service. | An attacker who also steals the manifest key can re-sign. In the in-memory demo the index is rebuilt at each start, so there is nothing older to compare with, and the page says so. |
| T10 | Password or API key guessing | PBKDF2-SHA256 with 600,000 iterations, 14-character minimum and common-password check. 5 failures lock the account for 15 minutes, 20 failures from one address block it, for passwords, MFA codes and API keys. Same error message for unknown users and wrong passwords. Constant-time comparisons. Per-user rate limit. | Counters live in one process. Several replicas need a shared store. |
| T11 | Stolen password | TOTP second factor (RFC 6238), required for every person, set up by QR code at first sign-in. Each code works once. Service accounts cannot use the web sign-in. | TOTP secrets are protected by file permissions, not encrypted. Phishing of a live code is still possible. |
| T12 | Session theft or fixation, cross-site requests | Session cookie `HttpOnly`, `Secure`, `SameSite=Strict`, 30-minute idle and 8-hour absolute expiry, new token after sign-in, only a hash of the token kept on the server. Requests with a cookie from another origin are refused. Disabling an account or changing its roles ends its sessions. | Sessions are in memory, so a restart signs everyone out. |
| T13 | Malicious or oversized file in the documents folder | Size, page and row limits, refusal of Office archives that expand to more than 200 MB (zip bomb), encrypted PDFs refused, unsupported formats skipped and reported. Files without roles are visible to the security team only. | Parsers (pypdf, python-docx, openpyxl) can have their own vulnerabilities: keep them patched. |
| T14 | Misuse of administration rights | A separate `admin` role that manages accounts but reads no documents. Admins cannot disable themselves or remove their own admin role. Every account change is logged with who did it. | One admin can still create an account with any role. A four-eyes approval is not implemented. |
| T15 | Audit log edited to hide traces, or becoming a leak | Each line carries the SHA-256 of the previous one: an edited, removed or reordered line breaks the chain (`python -m srag.audit`). Questions and feedback comments are stored masked, with a SHA-256 of the original question. | Someone able to rewrite the whole file can rebuild a chain. Forward the log to the SIEM as it is written. |
| T16 | Cross-site scripting through model output or document text | The web page inserts answers and excerpts with `textContent` only. Strict Content Security Policy (`script-src 'self'`, no inline script, `frame-ancestors 'none'`), `X-Content-Type-Options`, no caching of API responses. The session cookie cannot be read by JavaScript and nothing is kept in browser storage. | A compromised API could still serve a malicious page |
| T17 | Vulnerable dependencies or image | Pinned dependencies, Trivy scan of the image in CI (fails on fixable critical issues) | New vulnerabilities appear after the scan |

## Detection

Every request writes one JSON line to `logs/audit.jsonl`: `ask`, `blocked_injection`, `login_success`, `login_failed`, `mfa_failed`, `mfa_enrolled`, `account_locked`, `auth_failed`, `ip_blocked`, `csrf_blocked`, `rate_limited`, `user_created`, `user_updated`, `feedback`, `file_skipped`, `llm_unavailable`, `integrity_failed`, `startup`. The file is designed to be collected by a SIEM. [`deploy/wazuh`](deploy/wazuh) contains Wazuh rules that raise alerts on password guessing, locked accounts, repeated injection attempts, blocked cross-site requests, account changes and integrity failures.

## Production checklist

- [ ] Generate strong values for `POSTGRES_PASSWORD` and `SRAG_MANIFEST_KEY`, keep them in a secret manager
- [ ] Pin the Ollama image version and set `SRAG_OLLAMA_MODEL_DIGEST`
- [ ] Put the API behind HTTPS (reverse proxy) and connect the sign-in to the company directory (OpenID Connect) for large deployments
- [ ] Encrypt the authenticator secrets in `config/users.json` with a key from a secret manager
- [ ] Delete the demo accounts and create real ones from the administration page
- [ ] Encrypt the database and Ollama volumes at rest
- [ ] Back up the source documents and the manifest. The index can always be rebuilt from them.
- [ ] Forward `logs/audit.jsonl` to the SIEM and enable the Wazuh rules
- [ ] Review document roles before every ingestion

## Reporting a vulnerability

Please open a private security advisory on GitHub rather than a public issue.
