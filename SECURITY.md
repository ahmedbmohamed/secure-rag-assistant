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
| T9 | Index or model tampered with | HMAC-signed manifest of every document hash, checked at startup. Optional pinned model digest checked against Ollama. The service refuses to start on any difference. | An attacker who also steals the manifest key can re-sign |
| T10 | Brute force on API keys, API abuse | Keys compared in constant time, failed attempts logged with the client IP, per-user rate limit (30 requests per minute by default) | The limit is per process. Use a gateway for several replicas. |
| T11 | Audit log becomes a leak itself | Questions are stored masked, with a SHA-256 of the original | The masked text can still be sensitive |
| T12 | Cross-site scripting through model output or document text | The web page inserts answers and excerpts with `textContent` only. Strict Content Security Policy (`script-src 'self'`, no inline script, `frame-ancestors 'none'`), `X-Content-Type-Options`, no caching of API responses. The API key stays in memory, not in browser storage. | A compromised API could still serve a malicious page |
| T13 | Vulnerable dependencies or image | Pinned dependencies, Trivy scan of the image in CI (fails on fixable critical issues) | New vulnerabilities appear after the scan |

## Detection

Every request writes one JSON line to `logs/audit.jsonl`: `ask`, `blocked_injection`, `auth_failed`, `rate_limited`, `llm_unavailable`, `integrity_failed`, `startup`. The file is designed to be collected by a SIEM. [`deploy/wazuh`](deploy/wazuh) contains Wazuh rules that raise alerts on repeated failed authentication, repeated injection attempts and integrity failures.

## Production checklist

- [ ] Generate strong values for `POSTGRES_PASSWORD` and `SRAG_MANIFEST_KEY`, keep them in a secret manager
- [ ] Pin the Ollama image version and set `SRAG_OLLAMA_MODEL_DIGEST`
- [ ] Put the API behind HTTPS (reverse proxy) and an identity provider instead of static API keys
- [ ] Encrypt the database and Ollama volumes at rest
- [ ] Back up the source documents and the manifest. The index can always be rebuilt from them.
- [ ] Forward `logs/audit.jsonl` to the SIEM and enable the Wazuh rules
- [ ] Review document roles before every ingestion

## Reporting a vulnerability

Please open a private security advisory on GitHub rather than a public issue.
