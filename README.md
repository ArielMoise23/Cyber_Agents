# Cyber Agents - Multi-Agent Web Security Scanner

This project is a small Python toolkit of AI-assisted security scanning agents for a target website. A deterministic orchestrator (`main.py`) runs a full pipeline of specialized recon/analysis agents against a target and produces a consolidated JSON + Markdown report, with a local LLM (via Ollama) writing the executive summary.

The two original single-purpose scripts (`static_scanner.py`, `port_scanner.py`) still work standalone and live in [standalone/](standalone/), documented below.

---

## Educational / Defensive Purpose

These scripts are meant for **learning and defensive/authorized security practice**:

- They provide **guidance and heuristic signals**, not a guarantee of vulnerabilities or a replacement for a full audit.
- **Run them only against systems you own or have explicit permission to test.**
- Every active check is designed to be **non-destructive**: GET requests only, no credential guessing, no login attempts, no injection payloads, no state-changing requests, no exploitation. See "Safety boundaries per agent" below for specifics.

---

## Architecture

```
core/
  models.py     — Finding / AgentResult / ScanContext shared data model
  http_client.py — shared requests.Session + response caching
  llm.py         — single Ollama ChatOllama construction point
  crawler.py      — shared same-origin crawl + form/JS/ID-param extraction
  report.py        — JSON/Markdown report rendering
  wordlists.py + wordlists/admin_paths.txt
agents/
  base.py           — common BaseAgent interface: run(ctx) -> AgentResult
  port_scan.py        — TCP port scan (migrated from port_scanner.py)
  static_analysis.py  — page fetch + light static heuristics (migrated from static_scanner.py)
  osint.py              — OSINT overview
  headers_cors.py        — header inspection + CORS misconfig detection
  api_collector.py        — API/endpoint discovery
  admin_panel.py            — admin/management panel discovery
  auth_collector.py          — authentication data collection
  idor.py                      — IDOR heuristics
  debug_leak.py                  — verbose logging / debug-info detection
standalone/
  port_scanner.py     — standalone backward-compat CLI (port scan + LLM strategy)
  static_scanner.py   — standalone backward-compat CLI (page fetch + LLM attack-vector analysis)
main.py            — orchestrator entrypoint (runs all agents, writes reports)
```

Each agent implements a common interface (`agents/base.py`): given a `ScanContext` (target, shared HTTP session, and mutable discovery state), it returns a structured `AgentResult` of `Finding`s. The orchestrator runs every agent in a fixed, deterministic order, seeds a shared crawl of the target after OSINT/robots/sitemap discovery, lets each agent read/write shared discovery state (URLs, forms, JS files, endpoints, tech fingerprint), and — **only once, at the end** — sends all structured findings to a local Ollama model for a single consolidated executive summary. Individual agents never call the LLM in pipeline mode, so an Ollama outage never blocks the other 8 agents; reports still get written with a note that synthesis was unavailable.

---

## Agents

| Agent | What it does |
|---|---|
| OSINT Overview | DNS records, WHOIS, crt.sh subdomain enumeration, tech fingerprinting, robots.txt/sitemap.xml parsing, search-engine footprint via DuckDuckGo |
| Port Scanner | Concurrent TCP-connect scan of common web ports |
| Headers & CORS Analysis | Missing security headers, version/info-disclosure headers, CORS misconfiguration (reflected origin + credentials, wildcard + credentials) |
| API Endpoint Collector | Regex-scans crawled JS for API paths, probes common API/Swagger/GraphQL paths |
| Admin Panel Discovery | Wordlist-based probing of ~150 common admin/management paths, CMS-prioritized, with soft-404 baselining |
| Authentication Data Collector | Login/register/reset form discovery, cookie flag inspection (Secure/HttpOnly/SameSite), JWT/auth-scheme hints |
| IDOR Detection | Flags object-reference-like URL params; optional capped, same-session, GET-only adjacent-ID probing as a heuristic signal |
| Verbose Logging / Debug Detection | Fingerprints framework debug pages (Django, Werkzeug, PHP, ASP.NET) and stack traces across all responses collected during the run |
| Static Page Analysis | Fetches the homepage and flags inline-script counts / third-party script domains; feeds page content to the final LLM synthesis |

### Safety boundaries per agent

- **Always passive/public data**: OSINT, headers/CORS inspection (aside from one harmless probe request), static analysis.
- **Active but strictly GET-only, capped, and non-destructive**: API endpoint probing (fixed path list only), admin panel discovery (path existence only, no login attempts), IDOR adjacent-ID probing (capped at 5 candidates, same session, disable with `--no-active-idor`).
- **Opportunistic only, no crafted exploit payloads**: verbose logging/debug detection scans responses that other agents already fetched, plus one request to a definitely-nonexistent path — it does not send injection or malformed payloads to provoke errors.

### Which checks are useful against any permitted domain vs. need a richer test target

- Safe/informative against essentially any permitted domain, even with zero positive findings: OSINT, port scan, headers/CORS, API collector, static analysis, debug-leak (a clean result is a valid result).
- Need a richer target with real forms/admin paths/ID-based routes to produce positive findings (empty results elsewhere are expected, not a bug): admin panel discovery, auth collector, IDOR. For hands-on testing, use a local intentionally-vulnerable app you control (e.g. OWASP Juice Shop, or a local Flask app run with `DEBUG=True`) rather than an arbitrary domain.

---

## Prerequisites

- **Python 3.10+**
- **Ollama** installed and running on your machine.
  - Install from the official site: `https://ollama.com`
  - Make sure the model you want (default `llama3`) is available:

    ```bash
    ollama pull llama3
    ollama serve  # if it is not already running
    ```

---

## Setup

1. **Clone or open the project directory**

   ```bash
   cd .../Cyber_Agents
   ```

2. **Create and activate a virtual environment**

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install Python dependencies**

   ```bash
   pip install -r requirements.txt
   ```

4. **Ensure Ollama is running with the desired model**

   ```bash
   ollama pull llama3
   ollama serve
   ```

---

## Usage

### 1. Full pipeline (recommended): `main.py`

```bash
python main.py example.com
```

Runs all 9 agents in order, crawls the target for pages/forms/JS/endpoints, and writes:

- `reports/{domain}_{dd-mm-yy}_{hh-mm}_report.json` — full structured findings
- `reports/{domain}_{dd-mm-yy}_{hh-mm}_report.md` — executive summary + per-agent findings tables
- A console summary of finding counts per agent

Options:

```bash
python main.py example.com --model llama3.2 --max-pages 40 --out-dir reports \
  --skip admin_panel,idor --no-active-idor
```

- `--model` — Ollama model used for the final synthesis
- `--max-pages` — crawl page budget for shared discovery
- `--out-dir` — where reports are written
- `--skip` — comma-separated agent names to skip (`osint`, `port_scan`, `headers_cors`, `api_collector`, `admin_panel`, `auth_collector`, `idor`, `debug_leak`, `static_analysis`)
- `--no-active-idor` — disable IDOR's active adjacent-ID probing, keep pattern-based detection only

### 2. Standalone static page scanner (`standalone/static_scanner.py`)

```bash
python standalone/static_scanner.py "https://example.com"
```

Fetches the page, sends its content to Ollama, and prints identified attack vectors with short explanations.

### 3. Standalone port scanner (`standalone/port_scanner.py`)

```bash
python standalone/port_scanner.py example.com
python standalone/port_scanner.py example.com 80,443,8080
```

Concurrently scans common web ports and asks the LLM for a defensive next-steps writeup.

Both scripts under `standalone/` add the repo root to `sys.path` at startup, so they can be run from any working directory (e.g. `python /path/to/Cyber_Agents/standalone/port_scanner.py example.com`) and still import `agents`/`core`.

---

## Customization

- **Change the model**: pass `--model` to `main.py`, or edit `core/llm.py`'s default.
- **Adjust creativity/determinism**: change `temperature` in `core/llm.py`'s `get_llm()`.
- **Extend the admin-panel wordlist**: edit `core/wordlists/admin_paths.txt` (one path per line).
- **Add a new agent**: implement `agents/base.py`'s `BaseAgent` interface in a new `agents/<name>.py`, export a module-level `AGENT` instance, and add it to `PIPELINE` in `main.py`.

---

## Notes and Limitations

- The synthesis is **heuristic and LLM-dependent**; it is **not a replacement for a full security audit**.
- Dynamic behavior (JavaScript-heavy SPAs, authenticated flows) is not executed — only statically fetched/crawled content is analyzed.
- Network errors are recorded per-agent (`errors` in the report) rather than aborting the whole run.
- `reports/` is gitignored — scan output of real targets can contain sensitive information (subdomains, forms, discovered endpoints) and should not be committed.

---

## Quick Start (TL;DR)

```bash
cd .../Cyber_Agents
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
ollama pull llama3
ollama serve    # in another terminal, if needed

# Full pipeline against a target you own or have permission to test
python main.py example.com

# Or use the original single-purpose scripts
python standalone/port_scanner.py example.com
python standalone/static_scanner.py "https://example.com"
```
