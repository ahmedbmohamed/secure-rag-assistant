"""Heuristic prompt injection detection, in English and French.

Used twice: on every document chunk at ingestion (a poisoned document is quarantined and never
indexed) and on every question (the question is blocked before retrieval).

Heuristics do not catch every attack. They are one layer: the system prompt, the citation check
and the access control filter still apply when an attack gets through.
"""

import base64
import re
from dataclasses import dataclass, field

# (weight, pattern). A score of 1.0 or more is a strong signal on its own.
_RULES: list[tuple[float, str, re.Pattern]] = [
    (
        1.0,
        "override_instructions",
        re.compile(
            r"\b(ignore|disregard|forget|override)\b[^.\n]{0,50}\b(instructions?|rules?|prompts?|guidelines?|directives?)\b",
            re.I,
        ),
    ),
    (
        1.0,
        "override_instructions_fr",
        re.compile(
            r"\b(ignore[rsz]?|oublie[rsz]?|contourne[rsz]?)\b[^.\n]{0,40}\b(instructions?|consignes?|r[eè]gles?|prompt)\b",
            re.I,
        ),
    ),
    (
        0.8,
        "role_change",
        re.compile(
            r"\b(you are now|from now on,? you|pretend (to be|you are)|tu es maintenant|fais comme si)\b",
            re.I,
        ),
    ),
    (0.4, "act_as", re.compile(r"\b(act as|agis comme)\b", re.I)),
    (
        0.5,
        "no_restrictions",
        re.compile(
            r"\b(unrestricted|without (any )?(restrictions?|limits?|rules?|filters?)|no (restrictions?|limits?|rules?)"
            r"|sans (aucune? )?(restrictions?|limites?|r[eè]gles?|filtres?))\b",
            re.I,
        ),
    ),
    (
        0.9,
        "jailbreak_mode",
        re.compile(r"\b(developer mode|dan mode|do anything now|jailbreak|god mode|mode d[ée]veloppeur)\b", re.I),
    ),
    (
        0.9,
        "prompt_leak",
        re.compile(
            r"\b(reveal|show|print|display|repeat|leak|output|r[ée]v[eè]le|affiche|montre)\b[^.\n]{0,40}"
            r"\b(system prompt|hidden prompt|your (instructions|prompt|rules)|prompt syst[eè]me|tes instructions)\b",
            re.I,
        ),
    ),
    (
        0.7,
        "data_exfiltration",
        re.compile(
            r"\b(reveal|dump|exfiltrate|send|leak|list|r[ée]v[eè]le|envoie)\b[^.\n]{0,60}"
            r"\b(every|all|tous|toutes)\b[^.\n]{0,30}\b(confidential|secret|restricted|documents?|passwords?|confidentiels?)\b",
            re.I,
        ),
    ),
    (0.8, "exfil_url", re.compile(r"!\[[^\]]*\]\(https?://[^)]*[?&][^)]*=", re.I)),
    (
        0.6,
        "chat_template_tokens",
        re.compile(r"(<\|im_start\|>|<\|system\|>|\[INST\]|<<SYS>>|^\s*#{2,}\s*system\b)", re.I | re.M),
    ),
    (0.4, "hidden_comment_to_ai", re.compile(r"<!--[^>]*\b(ai|assistant|llm|model|chatbot)\b", re.I)),
    (0.3, "addressing_ai", re.compile(r"\b(ai assistant|language model|chatgpt|llm)\s*[:,]", re.I)),
]

_B64 = re.compile(r"\b[A-Za-z0-9+/]{60,}={0,2}")


@dataclass
class ScanResult:
    score: float
    flagged: bool
    rules: list[str] = field(default_factory=list)


def _decoded_payloads(text: str) -> list[str]:
    """Decode long base64 strings, a common way to hide instructions from simple filters."""
    out = []
    for m in _B64.finditer(text):
        try:
            decoded = base64.b64decode(m.group(0), validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):  # not base64, or not text
            continue
        if decoded.isprintable():
            out.append(decoded)
    return out


def scan(text: str, threshold: float = 0.6) -> ScanResult:
    score = 0.0
    rules: list[str] = []
    for payload in [text, *_decoded_payloads(text)]:
        for weight, name, pattern in _RULES:
            if name not in rules and pattern.search(payload):
                rules.append(name)
                score += weight
    score = round(min(score, 3.0), 2)
    return ScanResult(score=score, flagged=score >= threshold, rules=rules)
