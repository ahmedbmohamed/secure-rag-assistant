"""LLM access through LangChain, with a fail-closed rule.

If the configured LLM cannot answer, the request fails with LLMUnavailable. There is no automatic
fallback to another provider: an outage must never send data somewhere it was not meant to go.
"""

import httpx
from langchain_core.language_models import BaseChatModel
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate

from srag.config import Settings

_PROMPT = ChatPromptTemplate.from_messages([("system", "{system}"), ("human", "{user}")])


class LLMUnavailable(RuntimeError):
    """The LLM did not answer. The request is refused rather than rerouted."""


class ChatLLM:
    def __init__(self, model: BaseChatModel, name: str, mode: str) -> None:
        self._chain = _PROMPT | model | StrOutputParser()
        self.name = name
        self.mode = mode

    def generate(self, system: str, user: str) -> str:
        try:
            return self._chain.invoke({"system": system, "user": user})
        except Exception as exc:  # noqa: BLE001, any provider error means the same thing here
            raise LLMUnavailable(f"{self.mode} LLM unavailable: {type(exc).__name__}") from exc


def make_llm(settings: Settings) -> ChatLLM:
    if settings.llm_mode == "cloud":
        from langchain_openai import ChatOpenAI

        model = ChatOpenAI(
            base_url=settings.cloud_base_url,
            api_key=settings.cloud_api_key,
            model=settings.cloud_model,
            temperature=0,
            timeout=settings.llm_timeout_s,
            max_retries=1,
        )
        return ChatLLM(model, settings.cloud_model or "cloud", "cloud")

    from langchain_ollama import ChatOllama

    model = ChatOllama(
        model=settings.ollama_model,
        base_url=settings.ollama_url,
        temperature=0,
        num_ctx=8192,
        client_kwargs={"timeout": settings.llm_timeout_s},
    )
    return ChatLLM(model, settings.ollama_model, "local")


def ollama_model_digest(base_url: str, model: str) -> str | None:
    """Digest of the model served by Ollama, used to detect a replaced model file."""
    response = httpx.get(f"{base_url.rstrip('/')}/api/tags", timeout=10)
    response.raise_for_status()
    for entry in response.json().get("models", []):
        if entry.get("name") == model or entry.get("model") == model:
            return entry.get("digest")
    return None
