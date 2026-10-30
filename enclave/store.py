"""Labelled, encrypted chunk store with authorisation BEFORE retrieval.

The order matters (OWASP LLM02/LLM06): filter by label first, then rank by similarity,
then decrypt only what the subject may see. Ranking over everything and filtering after
leaks information through scores, counts, and timing.

Embeddings: a dependency-free hashed bag-of-words stand-in. Swap embed() for a local model
(e.g. sentence-transformers running inside the enclave) and the store for pgvector with a
row-level-security policy on the label columns.
"""
from dataclasses import dataclass
import hashlib
import math
import re

from .labels import Label, Subject, dominates, portion_label

DIM = 512
TOKEN = re.compile(r"[a-z0-9]+")


def embed(text: str) -> list[float]:
    v = [0.0] * DIM
    for tok in TOKEN.findall(text.lower()):
        h = int.from_bytes(hashlib.blake2b(tok.encode(), digest_size=4).digest(), "little")
        v[h % DIM] += 1.0 if h & 1 << 31 else -1.0
    n = math.sqrt(sum(x * x for x in v)) or 1.0
    return [x / n for x in v]


@dataclass
class Chunk:
    id: str
    doc: str
    label: Label
    vec: list
    blob: bytes


class EnclaveStore:
    def __init__(self, keyring, audit):
        self.keys, self.audit, self.chunks = keyring, audit, []

    def ingest(self, doc_id: str, text: str, doc_label: Label):
        n = 0
        for i, para in enumerate(p for p in text.split("\n\n") if p.strip()):
            lab, body = portion_label(para.strip(), doc_label)
            self.chunks.append(Chunk(f"{doc_id}#{i}", doc_id, lab, embed(body), self.keys.encrypt(lab.key_id(), body)))
            n += 1
        self.audit.log("ingest", doc=doc_id, label=doc_label.level, chunks=n)
        return n

    def search(self, subject: Subject, query: str, k=3):
        allowed = [c for c in self.chunks if dominates(subject, c.label)[0]]          # 1. authorise
        q = embed(query)
        ranked = sorted(allowed, key=lambda c: -sum(a * b for a, b in zip(q, c.vec)))[:k]   # 2. rank
        out = [{"id": c.id, "label": c.label.level, "text": self.keys.decrypt(c.label.key_id(), c.blob)} for c in ranked]
        self.audit.log("search", user=subject.user, clearance=subject.clearance, query_sha256=hashlib.sha256(query.encode()).hexdigest(),
                       returned=[c["id"] for c in out])                                     # 3. audit (query hashed, not stored)
        return out
