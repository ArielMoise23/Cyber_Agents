# Cyber Agents - Web Attack Vector Analyzer

This project is a small Python tool that:

- Fetches the HTML content of a given URL.
- Sends the page content to a local LLM running via Ollama.
- Asks the model to identify **potential security vulnerabilities / attack vectors** (e.g., XSS, SQL injection, directory traversal, authentication issues) and prints a short explanation for each.

The core logic lives in `agents.py`, which defines:

- `fetch_page_content(url)`: downloads the web page.
- `attack_prompt`: a LangChain `PromptTemplate` describing how to analyze the page.
- `extract_attack_vectors(url)`: orchestrates fetching the page and sending it to the LLM.

The project uses:

- `requests` for HTTP requests.
- `langchain-core` and `langchain-community` for prompt and model integration.
- `ChatOllama` to talk to a local Ollama model (e.g., `llama3`).

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

   If you prefer another model (e.g., `llama3.2` or `qwen2.5`), change the model name in `agents.py`:

   ```python
   llm = ChatOllama(model="llama3", temperature=0.2)
   ```

---

## Usage

With the virtual environment active and Ollama running:

```bash
python agents.py "https://example.com"
```

What happens:

1. The script prints progress messages:
   - `[1/3] Fetching page content from ...`
   - `[2/3] Page content fetched (...)`
   - `[3/3] Sending content to model, this may take a moment...`
   - `[✔] Analysis complete.`
2. The local LLM analyzes the page content using the `attack_prompt`.
3. The identified **attack vectors** and explanations are printed to the terminal.

### Command-line arguments

- **Required**: a single URL to analyze.

If you call the script without arguments, you will see:

```bash
Usage: python agents.py <url>
```

---

## Customization

- **Change the model**: edit the `ChatOllama` line in `agents.py`:

  ```python
  llm = ChatOllama(model="llama3", temperature=0.2)
  ```

- **Adjust creativity / determinism**:
  - Increase `temperature` for more diverse answers.
  - Decrease towards `0.0` for more deterministic outputs.

- **Modify the security analysis prompt**:
  - Edit the `attack_prompt` template string in `agents.py` to:
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
python agents.py "https://example.com"
```

