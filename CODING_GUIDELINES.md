# Coding Guidelines — AI-SecOps Portfolio

Context and conventions for anyone (human or AI agent) working in this repo. These
are derived from a full review of the five pipelines; follow them so the next change
doesn't reintroduce a fixed problem.

## 1. Secrets & config

- **Never hardcode secrets.** All credentials live in `~/.ai_intel_config` (gitignored);
  ship only `.ai_intel_config.example` with placeholders. This is already done — keep it.
- **Validate required keys at startup**, not mid-run. A pipeline that emails should confirm
  `GMAIL_USER`, `GMAIL_APP_PASSWORD`, `EMAIL_TO` (and `GROQ_API_KEY`) exist before doing work,
  so a missing key fails fast with a clear message instead of a `KeyError` after the API spend.
- **One config parser, one behavior.** The five pipelines each parse the config file slightly
  differently (some skip `#` comments, some don't). Prefer a single shared loader; at minimum
  every loader must skip blank/`#` lines and strip quotes identically.
- **The LLM model is config, not a literal.** Groq's model catalog changes; a hardcoded id
  (e.g. the legacy `qwen/qwen3.8-27b`) silently 404s every call. Read the model from config
  (`GROQ_MODEL`) with a documented current default, and keep it in ONE place per pipeline.
  Verify the id against <https://console.groq.com/docs/models> before relying on it.

## 2. Untrusted input

- **Parse untrusted XML with `defusedxml`, never `xml.etree`.** RSS/Atom feeds are remote and
  attacker-influenceable; the stdlib parser is vulnerable to entity-expansion / XXE.
- **URL-encode everything interpolated into a request URL.** Actor aliases and pulse ids contain
  spaces and untrusted characters — use `requests`' `params=` for query strings and
  `urllib.parse.quote` for path segments. Never f-string raw values into a URL.
- **Access external JSON defensively.** Use `.get(...)` with skips for missing keys so one
  malformed API item doesn't kill the whole run.
- **Treat model/feed/IOC text as data, not instructions.** Content pulled from HF model names,
  CVE descriptions, or OTX pulses is interpolated into LLM prompts — delimit it and instruct the
  model to treat it as untrusted data (prompt-injection surface).

## 3. PII & DLP

- **Never persist or display raw PII.** The DLP audit must not write un-masked request bodies to
  disk in cleartext, and reports must fully redact any leaked value (no `value[:4]` prefixes).
- **Credit-card detection must be Luhn-gated and ReDoS-safe.** Use bounded quantifiers (`{12,18}`,
  not `*?`) and validate every candidate with Luhn before counting it — otherwise phone numbers,
  order ids, and timestamps inflate the metric.
- **Measure what you claim.** A "DLP effectiveness" metric must compare the *gateway-masked* logged
  request against the *original* payload — not whether the LLM echoed PII in its response.
- Detection logic belongs in an importable, unit-tested module (see `4-DLP-Gateway/dlp_detect.py`).

## 4. State, dedup & external APIs

- **Write dedup/cache state only AFTER successful dispatch.** Writing "seen" hashes before the
  email/report succeeds means a failed run permanently drops those items from the next run's
  "new" set. Persist on success.
- **Report the actual new items, not a count-slice.** `items[:new_count]` is not "the new items" —
  have the insert return the rows it actually inserted.
- **Every network call needs a timeout and a bounded retry/backoff.** A missing `timeout=` can hang
  a cron run forever; a single 429 should not silently fail the whole pipeline.
- **Handle pagination.** NVD/OTX/HF cap results per page — loop until exhausted or record that the
  result was truncated in the report.
- **Use a context manager / `finally` for DuckDB connections** so an exception can't leak or lock
  the database file.

## 5. Structure & tooling

- **Name modules so they can be imported and tested.** Leading-dot, hyphenated filenames
  (`.threat-intel.py`) are hidden from tooling and cannot be `import`ed, which blocks unit tests.
  Prefer `snake_case.py`; if a hidden deploy target is required, keep the logic in an importable
  module and deploy via a thin wrapper.
- **Declare dependencies.** Everything imported must be in `requirements.txt`, pinned with `~=`.
- **Extract magic numbers** (batch sizes, CVSS thresholds, token caps, truncation limits) into
  named module-level constants.
- **Prefer a dataclass/dict over 14-positional-arg functions** (the email/report signatures).

## 6. Testing & lint

- Pure functions (PII detection, Luhn, CVSS extraction, dedup keys) must have **offline** unit
  tests — no network, no external DB. Start from `tests/`.
- Run `ruff check .` and `pytest` before committing.

## 7. Commits

- Conventional Commits (`feat:`, `fix:`, `refactor:`, `chore:`, `docs:`, `test:`, `perf:`).
- Imperative subject ≤ 50 chars; body explains *what* and *why*.
