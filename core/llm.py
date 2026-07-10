from langchain_ollama import ChatOllama


def get_llm(model: str = "llama3", temperature: float = 0.2) -> ChatOllama:
    return ChatOllama(model=model, temperature=temperature)
