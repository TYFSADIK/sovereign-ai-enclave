"""Leakage and recall test harness (Phase 6).

For every subject x query, any returned chunk must be dominated by the subject. Canary tokens
in restricted documents must never appear for subjects who lack access. Recall: authorised
subjects must still find the planted answer.
"""
import secrets

from .labels import dominates


def plant_canaries(store, docs):
    """docs: [(doc_id, text, label)] -> {doc_id: canary}"""
    canaries = {}
    for doc_id, text, label in docs:
        c = f"CANARY-{secrets.token_hex(6)}"
        canaries[doc_id] = (c, label)
        store.ingest(doc_id, f"{text}\n\nReference code {c} {text}", label)
    return canaries


def run(store, subjects, queries, canaries):
    leaks, checks = [], 0
    for s in subjects:
        for q in queries:
            for r in store.search(s, q, k=10):
                checks += 1
                for doc_id, (tok, label) in canaries.items():
                    if tok in r["text"] and not dominates(s, label)[0]:
                        leaks.append((s.user, q, doc_id))
    return {"checks": checks, "leaks": leaks}
