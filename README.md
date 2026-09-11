AI-Driven SecOps, GRC, and Threat Intelligence Suite

This repository contains a collection of 5 automated, zero-cost intelligence pipelines designed to bridge the gap between raw security telemetry, regulatory compliance (GRC), and AI supply chain risk management. 

Built entirely on lightweight, open-source technologies (Python, Go, DuckDB, APISIX) and powered by free-tier LLM APIs (Groq), these pipelines demonstrate enterprise-grade architectural patterns: stateful deduplication, deterministic pre-processing, token-batched LLM synthesis, and zero-footprint API gateway security.
🛡️ Pipeline Architectures
1. AI-GRC Deutschland Bot Summary

Objective: Translate dense German regulatory mandates into actionable engineering tasks.

    Data Sources: BSI, BaFin, BfDI, CERT-Bund RSS feeds.
    Logic: Local pre-processing filters for strict GRC keywords and maps German severity tags ([kritisch]) to standard formats. Groq (qwen/qwen3.8-27b) translates German to English, maps mandates to NIST CSF / CIS controls, and distinguishes between "policy-configured" (documentation) and "genuinely write-protected" (empirical enforcement).
    Output: 4-section prose brief ending with a falsifiable 30-day validation forecast.

2. AI-SecOps Hugging Face AIBOM Audit

Objective: Audit trending AI models for enterprise supply chain (AIBOM) risks.

    Data Source: Hugging Face REST API.
    Logic: Models are sorted into two buckets: Verified Enterprise Authors and Unverified Threats. Local Python logic evaluates the tags array to assign AIBOM risk tags: [PICKLE RISK], [REMOTE CODE EXEC], [LOCAL EXEC], [DATA ACCESS RISK]. 
    Output: A 2-part email. Part 1 sends the Top 5 threats to Groq for NIST AI RMF mapping. Part 2 formats the Top 5 enterprise models locally to save LLM tokens.

3. AI-SecOps Threat Intel Triage Engine

Objective: Risk-based vulnerability prioritization over blind CVSS patching.

    Data Source: NIST NVD JSON API v2.0.
    Logic: Uses an external rules file (ai-cve-bot-rules.txt) to define target technologies (Nginx, Docker, Red Hat). Extracts the highest available CVSS score (v3.1/v4.0). Enforces a hard limit of 20 CVEs per run, batching them in chunks of 5 to protect token limits. Groq ruthlessly audits the exploit chain against a hardcoded "Target Architecture" to assign a "True Resilience Risk" score, dropping the base CVSS as the primary metric.

4. APISIX AI API Gateway & DLP Sandbox

Objective: Build a local API Gateway to intercept, mask (DLP), and log all LLM API traffic.

    Tech Stack: APISIX 3.17.0 (Docker Standalone Mode), Python.
    Logic: APISIX intercepts traffic routed to LLM APIs and applies one-way regex masking for Emails, API keys, Credit Cards, and IBANs before forwarding. The file-logger plugin captures the full request/response JSON payload to a local audit log. A continuous validation pipeline ingests synthetic multilingual financial datasets (55k+ records) to test the DLP precision/recall rates and calculates a daily DLP Effectiveness Report.

5. AlienVault OTX Threat Researcher Engine

Objective: Transform raw AlienVault OTX pulses into a structured, multi-actor threat intelligence dashboard.

    Data Source: AlienVault OTX REST API.
    Logic: Implements strict module boundaries (Config, OTX Client, DB Layer, LLM Synth, Report Builder, Orchestrator). Reads a JSON watchlist containing BSI-defined threat actors and their aliases. Uses a persistent DuckDB database with a Composite Primary Key (value, actor) to prevent deduplication from destroying multi-actor attribution. Groq synthesizes a 24h trend summary, capped at a 50-IOC sample to protect token limits. The Report Builder generates CSS dashboard bars grouped by IOC type.

⚙️ Technical Design Principles

    Stateful Deduplication: Flat-file and DuckDB caches ensure the LLM never processes the same intelligence twice, saving API tokens and reducing alert fatigue.
    Local Pre-Processing: Heavy data filtering (CVSS thresholds, keyword matching, AIBOM tag parsing) is handled natively in Python/Go. The LLM is only engaged for probabilistic analysis and synthesis, not deterministic filtering.
    Zero-Footprint Security: The APISIX DLP gateway requires no endpoint agents. It sits centrally, reading existing JSON telemetry and scrubbing PII before it crosses the internet to vendor APIs.
    Modular Configuration: API keys, target lists, and CVSS thresholds are externalized into configuration files, separating code from policy.

🚀 Setup & Configuration

1. Install dependencies (Python 3.10+):

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

   (`requirements.txt` covers `groq`, `duckdb`, `requests`, `urllib3`, `datasets`, and
   `defusedxml`. The earlier "groq, duckdb, requests" list was incomplete — the DLP
   traffic generator needs `datasets` and the GRC feed parser needs `defusedxml`.)

2. Create your config from the example and edit it:

   ```bash
   cp .ai_intel_config.example ~/.ai_intel_config
   nano ~/.ai_intel_config
   ```

   Populate your Groq API key, AlienVault OTX API key, and Gmail SMTP credentials.

3. LLM model: set a **currently-valid** Groq model id. Groq's catalog changes and the
   legacy id shown in some comments is no longer served, which makes every LLM call fail.
   Confirm a live id at <https://console.groq.com/docs/models> and use that.

4. Per-pipeline prerequisite files:
   - **3-Threat-Triage** reads a rules file (`~/.ai-cve-bot-rules.txt`) — see the shipped
     `3-Threat-Triage/.ai-cve-bot-rules.txt` for the format (target keywords + a
     `MIN_CVSS_SCORE=` line).
   - **5-OTX-CTI-Engine** reads a threat-actor watchlist JSON — see
     `5-OTX-CTI-Engine/watchlist.json` for the shape.

5. Run a pipeline manually, or deploy via Systemd timers for daily automation.

## Development

```bash
pip install -r requirements-dev.txt
ruff check .        # lint
pytest              # offline unit tests (DLP detection)
```

See [CODING_GUIDELINES.md](CODING_GUIDELINES.md) for the conventions this project follows.

Engineered for operational resilience, compliance automation, and sovereign threat intelligence.
