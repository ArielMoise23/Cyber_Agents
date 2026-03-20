import requests
from langchain_core.prompts import PromptTemplate
from langchain_community.chat_models import ChatOllama

def fetch_page_content(url):
    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        return response.text
    except Exception as e:
        return f"Error fetching URL content: {e}"

# Define a prompt for extracting attack vectors from webpage text
attack_prompt = PromptTemplate(
    template="""Given the following web page content, analyze and list potential security vulnerabilities or attack vectors that may be relevant (e.g., XSS, SQL injection, directory traversal, authentication issues, etc.). Give a short explanation for each one identified.
    
Web Page Content:
-----------------
{page_content}

Attack Vectors:
""",
    input_variables=["page_content"],
)

def extract_attack_vectors(url, llm=None):
    print(f"[1/3] Fetching page content from {url} ...")
    content = fetch_page_content(url)
    if content.startswith("Error"):
        return content
    print(f"[2/3] Page content fetched ({len(content)} characters). Preparing analysis with Ollama...")

    # Use Ollama LLM if not provided
    if not llm:
        llm = ChatOllama(model="llama3", temperature=0.2)
    chain = attack_prompt | llm
    print("[3/3] Sending content to model, this may take a moment...")
    result = chain.invoke({"page_content": content})
    print("[✔] Analysis complete.")
    return result.content

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python static_scanner.py <url>")
    else:
        url = sys.argv[1]
        result = extract_attack_vectors(url)
        print(f"\nPotential Attack Vectors for {url}:\n")
        print(result)
