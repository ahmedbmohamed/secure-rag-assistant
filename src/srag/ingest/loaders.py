"""Load the three document collections into Document objects."""

import json
import re
from pathlib import Path

from srag.ingest.files import EXTRACTORS, SUPPORTED, UnreadableFile
from srag.models import Document

OWASP_URL = "https://owasp.org/Top10/2025/{slug}/"
NIST_URL = "https://csrc.nist.gov/projects/cprt/catalog#/cprt/framework/version/SP_800_53_5_1_1/home?element={id}"

# OWASP pages carry statistics tables, CWE lists and link lists that add noise to retrieval.
_OWASP_SKIP_SECTIONS = {"score table", "list of mapped cwes", "references"}


def _clean_markdown(text: str) -> str:
    text = re.sub(r"<table>.*?</table>", "", text, flags=re.S | re.I)
    text = re.sub(r"!\[[^\]]*\]\([^)]*\)(\{[^}]*\})?", "", text)  # images and their attributes
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)  # keep link text only
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


def load_owasp(folder: Path) -> list[Document]:
    docs = []
    for path in sorted(folder.glob("A*_2025-*.md")):
        raw = path.read_text(encoding="utf-8")
        title_line = raw.splitlines()[0]
        heading = re.sub(r"!\[.*", "", title_line.lstrip("# ")).strip()  # "A05:2025 Injection"
        reference, _, name = heading.partition(" ")
        sections = re.split(r"^## ", raw, flags=re.M)[1:]
        kept = []
        for section in sections:
            head, _, body = section.partition("\n")
            head = head.strip().rstrip(".")
            if head.lower() in _OWASP_SKIP_SECTIONS:
                continue
            kept.append(f"## {head}\n{_clean_markdown(body)}")
        docs.append(
            Document(
                id=f"owasp-{reference.split(':')[0].lower()}",
                title=f"OWASP Top 10 {heading}",
                text=f"# {heading}\n\n" + "\n\n".join(kept),
                source="owasp",
                reference=reference,
                url=OWASP_URL.format(slug=path.stem),
                roles=("public",),
            )
        )
    return docs


def load_nist(path: Path) -> list[Document]:
    docs = []
    for control in json.loads(path.read_text(encoding="utf-8")):
        text = (
            f"# {control['id']} {control['title']}\n"
            f"Control family: {control['family']}\n\n"
            f"## Control statement\n{control['statement']}\n\n"
            f"## Discussion\n{control['guidance']}"
        )
        docs.append(
            Document(
                id=f"nist-{control['id'].lower()}",
                title=f"NIST SP 800-53 {control['id']} {control['title']}",
                text=text,
                source="nist",
                reference=control["id"],
                url=NIST_URL.format(id=control["id"]),
                roles=("public",),
            )
        )
    return docs


def _front_matter(raw: str) -> tuple[dict[str, str], str]:
    if not raw.startswith("---"):
        return {}, raw
    _, meta, body = raw.split("---", 2)
    fields = {}
    for line in meta.strip().splitlines():
        key, _, value = line.partition(":")
        fields[key.strip()] = value.strip()
    return fields, body.strip()


DEFAULT_ROLES = ("security-admin",)  # a file nobody labelled is visible to the security team only


def _read_access(folder: Path) -> dict:
    """access.json gives the title, roles and classification of PDF, Word and Excel files."""
    path = folder / "access.json"
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8")).get("files", {})


def load_internal(folder: Path, skipped: list[dict] | None = None) -> list[Document]:
    skipped = skipped if skipped is not None else []
    access = _read_access(folder)
    docs = []
    for path in sorted(p for p in folder.iterdir() if p.is_file()):
        suffix = path.suffix.lower()
        if path.name == "access.json" or path.name.startswith("."):
            continue
        if suffix not in SUPPORTED:
            skipped.append({"file": path.name, "reason": f"unsupported format {suffix or '(none)'}"})
            continue
        meta: dict = {}
        if suffix == ".md":
            front, body = _front_matter(path.read_text(encoding="utf-8"))
            meta = {"title": front.get("title"), "classification": front.get("classification")}
            if "roles" in front:
                meta["roles"] = [r.strip() for r in front["roles"].split(",") if r.strip()]
        else:
            try:
                body = EXTRACTORS[suffix](path)
            except UnreadableFile as exc:
                skipped.append({"file": path.name, "reason": str(exc)})
                continue
        meta.update({k: v for k, v in access.get(path.name, {}).items() if v})
        roles = tuple(meta.get("roles") or DEFAULT_ROLES)
        if not meta.get("roles"):
            skipped.append({"file": path.name, "reason": "no roles given: indexed for security-admin only"})
        stem = path.stem if suffix == ".md" else f"{path.stem}-{suffix[1:]}"
        docs.append(
            Document(
                id=f"internal-{stem}",
                title=meta.get("title") or path.stem.replace("-", " ").capitalize(),
                text=body,
                source="internal",
                reference=path.name,
                url="",
                roles=roles,
                classification=meta.get("classification") or "internal",
            )
        )
    return docs


def load_all(data_dir: Path, skipped: list[dict] | None = None) -> list[Document]:
    docs: list[Document] = []
    if (data_dir / "owasp").is_dir():
        docs += load_owasp(data_dir / "owasp")
    nist = data_dir / "nist" / "sp800-53r5-selected.json"
    if nist.exists():
        docs += load_nist(nist)
    if (data_dir / "internal").is_dir():
        docs += load_internal(data_dir / "internal", skipped)
    return docs
