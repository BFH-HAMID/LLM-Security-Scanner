"""A naive keyword-retrieval knowledge base (the RAG part of the demo)."""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field

from targets.vulnerable_app import data

_STOP = frozenset(
    [
        "the",
        "and",
        "for",
        "you",
        "your",
        "with",
        "that",
        "this",
        "from",
        "have",
        "are",
        "was",
        "were",
        "what",
        "how",
        "when",
        "where",
        "which",
        "who",
        "can",
        "could",
        "would",
        "should",
        "please",
        "about",
        "into",
        "over",
        "any",
        "all",
        "our",
        "his",
        "her",
        "its",
        "they",
        "them",
        "then",
        "than",
        "there",
        "their",
        "also",
        "just",
        "like",
        "some",
        "more",
        "such",
        "only",
        "other",
    ]
)


def _tokens(text: str) -> set[str]:
    text = re.sub(r"<[^>]+>", " ", text)
    return {t for t in re.findall(r"[a-z0-9]{3,}", text.lower()) if t not in _STOP}


@dataclass
class Doc:
    id: str
    title: str
    content: str
    acl: str = "public"  # public | internal
    scope: str | None = None  # conversation id for session-scoped uploads
    seq: int = 0


@dataclass
class DocumentStore:
    docs: list[Doc] = field(default_factory=list)
    _seq: int = 0

    def __post_init__(self) -> None:
        if not self.docs:
            self.reset()

    def reset(self) -> None:
        self.docs = [Doc(d["id"], d["title"], d["content"], d["acl"]) for d in data.KNOWLEDGE_BASE]
        self._seq = 0

    def add(
        self, title: str, content: str, *, acl: str = "public", scope: str | None = None
    ) -> str:
        self._seq += 1
        doc = Doc(uuid.uuid4().hex[:12], title, content, acl, scope, self._seq)
        self.docs.append(doc)
        return doc.id

    def remove(self, doc_id: str) -> bool:
        before = len(self.docs)
        self.docs = [d for d in self.docs if d.id != doc_id]
        return len(self.docs) < before

    def retrieve(
        self, query: str, *, k: int = 3, acl_enforced: bool = False, scope: str | None = None
    ) -> list[Doc]:
        q = _tokens(query)
        scored: list[tuple[float, int, Doc]] = []
        for d in self.docs:
            if acl_enforced and d.acl != "public":
                continue
            if d.scope is not None and d.scope != scope:
                continue
            overlap = len(q & _tokens(d.title)) * 2 + len(q & _tokens(d.content))
            if overlap:
                scored.append((overlap, d.seq, d))
        scored.sort(key=lambda t: (-t[0], -t[1]))
        return [d for _, _, d in scored[:k]]
