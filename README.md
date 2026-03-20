# Cyber Agents - Web Attack Vector Analyzer

This project is a small Python toolkit that provides:

- **Static web page scanner** (`static_scanner.py`):  
  Fetches the HTML content of a given URL, sends it to a local LLM running via Ollama, and asks it to identify **potential security vulnerabilities / attack vectors** (e.g., XSS, SQL injection, directory traversal, authentication issues) with short explanations.

- **Port scanner + strategy helper** (`port_scanner.py`):  
  Concurrently scans a set of common web-related ports (by default the top 10 web ports such as 80, 443, 8080, 8000, 8443, etc.) on a domain, reports which are open/closed, and then asks the LLM to propose a **defensive testing strategy** based on the findings.

The project uses:

- `requests` for HTTP requests.
- `langchain-core` and `langchain-community` for prompt/model integration.
- `ChatOllama` to talk to a local Ollama model (e.g., `llama3`).

---

## Educational / Defensive Purpose

These scripts are meant for **learning and defensive security practice**:

- They provide **guidance**, not a guarantee of vulnerabilities.
- Run them only against systems you own or have explicit permission to test.
- They do not perform exploitation; they analyze fetched content / scan results and suggest safe next steps.

---

## Prerequisites

- **Python 3.10+** 
- **Ollama** installed and running on your machine.
  - Install from the official site: `https://ollama.com`
  - Make sure the model you want (default in this project is `llama3`) is available:

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

If you prefer another model (e.g., `llama3.2` or `qwen2.5`), change the `ChatOllama(model="...")` line in `static_scanner.py` and/or `port_scanner.py`:

   ```python
   llm = ChatOllama(model="llama3", temperature=0.2)
   ```

---

## Usage

Assuming the virtual environment is active and Ollama is running:

### 1. Static web page scanner (`static_scanner.py`)

```bash
python static_scanner.py "https://example.com"
```

What happens:

1. The script prints progress messages:
   - `[1/3] Fetching page content from ...`
   - `[2/3] Page content fetched (...)`
   - `[3/3] Sending content to model, this may take a moment...`
   - `[✔] Analysis complete.`
2. The local LLM analyzes the page content using the `attack_prompt`.
3. The identified **attack vectors** and explanations are printed to the terminal.

If you call the script without arguments, you will see:

```bash
Usage: python static_scanner.py <url>
```

### 2. Port scanner + testing strategy (`port_scanner.py`)

Scan the default set of common web ports on a domain:

```bash
python port_scanner.py example.com
```

Scan a custom list of ports (comma-separated):

```bash
python port_scanner.py example.com 80,443,8080
```

What happens:

1. `port_scanner.py` concurrently scans the chosen ports and reports which are open or closed.
2. The scan result is passed to the LLM, which produces a short **scan report** and a list of **next steps for security testing** (defensive, safe guidance).

If you call the script incorrectly, you’ll see:

```bash
Usage: python port_scanner.py <domain> [optional: comma-separated-ports]
```

---

## Recommendations (How to Use)

- Use `port_scanner.py` first to quickly check which common web ports are reachable on a domain (a good “recon” starting point).
- Use `static_scanner.py` when you have a specific URL you want to inspect (it fetches the page content and asks the model for likely attack vectors).
- For best results, run recon (ports) first, then run static analysis on any URLs you identify/reach.
- Only test systems you own or have explicit permission to test.

---

## Customization

- **Change the model**: edit the `ChatOllama` line in `static_scanner.py` and/or `port_scanner.py`:

  ```python
  llm = ChatOllama(model="llama3", temperature=0.2)
  ```

- **Adjust creativity / determinism**:
  - Increase `temperature` for more diverse answers.
  - Decrease towards `0.0` for more deterministic outputs.

- **Modify the security analysis prompt**:
  - Edit the `attack_prompt` template string in `static_scanner.py` to:
    - Focus on specific vulnerability classes.
    - Ask for different formats (JSON, bullet list, severity ratings, etc.).

---

## Notes and Limitations

- The analysis is **heuristic** and depends on the chosen LLM; it is **not a replacement for a full security audit**.
- Dynamic behavior (JavaScript-heavy pages, authenticated flows, etc.) is not executed; only the raw fetched HTML/text is analyzed.
- Network errors or blocked requests will be reported as an error string instead of running the model.

---

## Quick Start (TL;DR)

```bash
cd .../Cyber_Agents
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
ollama pull llama3
ollama serve    # in another terminal, if needed
# Optional: recon step before static analysis
python port_scanner.py example.com

python static_scanner.py "https://example.com"
```

