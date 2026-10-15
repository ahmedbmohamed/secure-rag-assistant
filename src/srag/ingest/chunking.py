"""Split documents into chunks that keep their section heading.

LangChain's markdown splitter cuts on headings first, then the recursive splitter cuts long
sections at paragraph and sentence boundaries. Each chunk is prefixed with its document title
and section, so a chunk read alone still says where it comes from.
"""

from langchain_text_splitters import MarkdownHeaderTextSplitter, RecursiveCharacterTextSplitter

from srag.models import Chunk, Document

_HEADERS = [("#", "h1"), ("##", "h2"), ("###", "h3")]


def chunk_document(doc: Document, chunk_size: int = 900, chunk_overlap: int = 120) -> list[Chunk]:
    by_heading = MarkdownHeaderTextSplitter(headers_to_split_on=_HEADERS, strip_headers=True)
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap,
        separators=["\n\n", "\n", ". ", " ", ""],
    )
    chunks: list[Chunk] = []
    for part in by_heading.split_text(doc.text):
        section = part.metadata.get("h3") or part.metadata.get("h2") or part.metadata.get("h1") or ""
        for piece in splitter.split_text(part.page_content):
            piece = piece.strip()
            if len(piece) < 40:
                continue
            ordinal = len(chunks)
            header = f"{doc.title} | {section}" if section and section not in doc.title else doc.title
            chunks.append(
                Chunk(
                    id=f"{doc.id}#{ordinal}",
                    doc_id=doc.id,
                    ordinal=ordinal,
                    text=f"[{header}]\n{piece}",
                    title=doc.title,
                    section=section,
                    source=doc.source,
                    reference=doc.reference,
                    url=doc.url,
                    roles=doc.roles,
                )
            )
    return chunks
