"""Settings, read from environment variables prefixed with SRAG_."""

import ipaddress
import os
import socket
from pathlib import Path
from typing import Literal
from urllib.parse import urlparse

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


def _default_home() -> Path:
    env = os.environ.get("SRAG_HOME")
    if env:
        return Path(env)
    source_root = Path(__file__).resolve().parents[2]
    if (source_root / "data").is_dir():
        return source_root
    return Path.cwd()


HOME = _default_home()


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SRAG_", env_file=".env", extra="ignore")

    # Storage. Without a database URL, an in-memory store is used (tests and quick demos).
    database_url: str | None = None
    data_dir: Path = HOME / "data"
    manifest_path: Path = HOME / "index" / "manifest.json"
    manifest_key: str = "change-me-in-production"

    # Embeddings: "fastembed" runs an ONNX model on the CPU, "hashing" needs no model (tests).
    embedder: Literal["fastembed", "hashing"] = "fastembed"
    embed_model: str = "BAAI/bge-small-en-v1.5"
    embed_cache_dir: Path | None = None

    # LLM. "local" keeps every byte on the machine. "cloud" is opt-in and always masks PII.
    llm_mode: Literal["local", "cloud"] = "local"
    ollama_url: str = "http://localhost:11434"
    ollama_model: str = "qwen2.5:3b"
    ollama_model_digest: str | None = None
    allow_cloud: bool = False
    cloud_base_url: str | None = None
    cloud_model: str | None = None
    cloud_api_key: str | None = None
    llm_timeout_s: float = 120.0

    # Retrieval
    top_k: int = 5
    candidates: int = 20
    min_score: float | None = None  # None means the default of the embedder
    chunk_size: int = 900
    chunk_overlap: int = 120

    # Guardrails
    injection_threshold: float = 0.6
    rate_limit_per_minute: int = 30

    # Users, audit
    users_file: Path = HOME / "config" / "users.json"
    audit_log: Path = HOME / "logs" / "audit.jsonl"

    @model_validator(mode="after")
    def _check_llm_mode(self) -> "Settings":
        if self.llm_mode == "cloud":
            if not self.allow_cloud:
                raise ValueError(
                    "Cloud mode sends (masked) data to a third party. Set SRAG_ALLOW_CLOUD=true to confirm this choice."
                )
            if not (self.cloud_base_url and self.cloud_model and self.cloud_api_key):
                raise ValueError("Cloud mode needs SRAG_CLOUD_BASE_URL, SRAG_CLOUD_MODEL and SRAG_CLOUD_API_KEY.")
        else:
            check_private_endpoint(self.ollama_url)
        return self

    @property
    def effective_min_score(self) -> float:
        if self.min_score is not None:
            return self.min_score
        return 0.55 if self.embedder == "fastembed" else 0.1


def is_private_host(host: str) -> bool:
    """True when the host is loopback or on a private network.

    A name that does not resolve here (for example a Docker service name used at build time)
    is accepted only if it has no dot, which rules out public domain names.
    """
    try:
        return _is_private_ip(ipaddress.ip_address(host))
    except ValueError:
        pass
    if host == "localhost":
        return True
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return "." not in host
    return all(_is_private_ip(ipaddress.ip_address(info[4][0])) for info in infos)


def _is_private_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return ip.is_loopback or ip.is_private or ip.is_link_local


def check_private_endpoint(url: str) -> None:
    host = urlparse(url).hostname or ""
    if not is_private_host(host):
        raise ValueError(
            f"Local mode requires the LLM to run on this machine or the private network, got '{host}'. "
            "Use cloud mode explicitly if data may leave the network."
        )


def get_settings(**overrides) -> Settings:
    return Settings(**overrides)
