"""Standalone CLI: fetch a URL and ask a local Ollama model to list potential attack vectors.

For a full multi-agent scan (recon, OSINT, admin panel discovery, IDOR heuristics, etc.),
use `python main.py <target>` instead. This script is kept for the original single-agent workflow.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from langchain_core.prompts import PromptTemplate

from agents.static_analysis import fetch_page_content
from core.llm import get_llm

ATTACK_PROMPT = PromptTemplate(
    template="""Given the following web page content, analyze and list potential security vulnerabilities or attack vectors that may be relevant (e.g., XSS, SQL injection, directory traversal, authentication issues, etc.). Give a short explanation for each one identified.

Web Page Content:
-----------------
{page_content}

Attack Vectors:
""",
    input_variables=["page_content"],
)


def extract_attack_vectors(url: str, llm=None) -> str:
    print(f"[1/3] Fetching page content from {url} ...")
    content = fetch_page_content(url)
    if content.startswith("Error"):
        return content
    print(f"[2/3] Page content fetched ({len(content)} characters). Preparing analysis with Ollama...")

    llm = llm or get_llm()
    chain = ATTACK_PROMPT | llm
    print("[3/3] Sending content to model, this may take a moment...")
    result = chain.invoke({"page_content": content})
    print("[✔] Analysis complete.")
    return result.content


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python standalone/static_scanner.py <url>")
    else:
        url = sys.argv[1]
        result = extract_attack_vectors(url)
        print(f"\nPotential Attack Vectors for {url}:\n")
        print(result)
