"""Trace records and behavioural signatures (plan section 4.2, version 1 subset).

Version 1 features per trace: token counts, a 128-function MinHash over
1-3-gram shingles, duration/event count, technique tags, indicators.
"""

from __future__ import annotations

import hashlib
import math
from collections import Counter
from dataclasses import dataclass, field


NUM_PERM = 128


def shingle_tokens(tokens: list[str], n_min: int = 1, n_max: int = 3) -> frozenset[str]:
    """Build 1-3-gram shingles from a token sequence (token-set input)."""
    out: set[str] = set()
    n = len(tokens)
    for width in range(n_min, n_max + 1):
        for i in range(n - width + 1):
            out.add(f"{width}g:" + "\x1f".join(tokens[i : i + width]))
    return frozenset(out)


def _perm_hash(shingle: str, perm: int, seed: int = 0) -> int:
    digest = hashlib.blake2b(
        f"{seed}:{perm}:{shingle}".encode("utf-8"), digest_size=8
    ).digest()
    return int.from_bytes(digest, "big")


def minhash_signature(
    shingles: frozenset[str], num_perm: int = NUM_PERM, seed: int = 0
) -> tuple[int, ...]:
    """Deterministic MinHash signature (empty set -> all-max signature)."""
    if not shingles:
        return tuple([2**64 - 1] * num_perm)
    return tuple(
        min(_perm_hash(s, p, seed) for s in shingles) for p in range(num_perm)
    )


def minhash_jaccard(a: tuple[int, ...], b: tuple[int, ...]) -> float:
    """Estimated Jaccard from two signatures (equal length required)."""
    if len(a) != len(b):
        raise ValueError("signatures must have equal length")
    if not a:
        return 0.0
    return sum(x == y for x, y in zip(a, b)) / len(a)


def exact_jaccard(a: frozenset[str], b: frozenset[str]) -> float:
    if not a and not b:
        return 0.0
    return len(a & b) / len(a | b)


def build_idf(doc_counts: list[Counter], n_docs: int | None = None) -> dict[str, float]:
    """Smoothed IDF over token-count vectors: log((N+1)/(df+1)) + 1."""
    n = n_docs if n_docs is not None else len(doc_counts)
    df: Counter = Counter()
    for counts in doc_counts:
        for tok in counts:
            df[tok] += 1
    return {tok: math.log((n + 1) / (freq + 1)) + 1.0 for tok, freq in df.items()}


def tfidf_cosine(a: Counter, b: Counter, idf: dict[str, float]) -> float:
    """Cosine similarity of TF-IDF weighted count vectors."""
    if not a or not b:
        return 0.0
    dot = 0.0
    na = 0.0
    nb = 0.0
    for tok, ca in a.items():
        wa = ca * idf.get(tok, 1.0)
        na += wa * wa
        cb = b.get(tok)
        if cb:
            dot += wa * cb * idf.get(tok, 1.0)
    for tok, cb in b.items():
        wb = cb * idf.get(tok, 1.0)
        nb += wb * wb
    if na == 0.0 or nb == 0.0:
        return 0.0
    return dot / (math.sqrt(na) * math.sqrt(nb))


@dataclass
class Trace:
    """Minimal version-1 trace record used by retrieval and scoring."""

    trace_id: str
    tokens: tuple[str, ...] = ()
    techniques: frozenset[str] = frozenset()
    indicators: frozenset[str] = frozenset()
    entities: frozenset[str] = frozenset()
    start_ts: float = 0.0
    end_ts: float = 0.0
    num_perm: int = NUM_PERM
    shingles: frozenset[str] = field(init=False)
    signature: tuple[int, ...] = field(init=False)
    token_counts: Counter = field(init=False)

    def __post_init__(self) -> None:
        self.shingles = shingle_tokens(list(self.tokens))
        self.signature = minhash_signature(self.shingles, self.num_perm)
        self.token_counts = Counter(self.tokens)

    @property
    def duration(self) -> float:
        return max(0.0, self.end_ts - self.start_ts)

    @property
    def event_count(self) -> int:
        return len(self.tokens)
