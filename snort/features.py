"""Trace features for v1: tokens, MinHash shingles, techniques, indicators.

Implements the plan section 4.2 v1 subset: TF-IDF token counts and a
128-function MinHash over 1-3-gram shingles, plus technique/indicator sets.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

N_MINHASH = 128


@dataclass
class Trace:
    tid: str
    tokens: list[str]
    techniques: set[str] = field(default_factory=set)
    indicators: set[str] = field(default_factory=set)
    ts: float = 0.0
    actor: str | None = None  # ground truth; None for E3/lawful-unlabelled
    minhash: list[int] = field(default_factory=list)

    def text(self) -> str:
        return " ".join(self.tokens)


def shingles(tokens: list[str], ns=(1, 2, 3)) -> set[str]:
    out: set[str] = set()
    for n in ns:
        for i in range(len(tokens) - n + 1):
            out.add(" ".join(tokens[i : i + n]))
    return out


def _func_hash(seed: int, shingle: str) -> int:
    h = hashlib.md5(f"{seed}:{shingle}".encode("utf-8")).digest()
    return int.from_bytes(h[:8], "big")


def minhash_signature(tokens: list[str], n: int = N_MINHASH) -> list[int]:
    sh = shingles(tokens) or {"<empty>"}
    return [min(_func_hash(s, g) for g in sh) for s in range(n)]


def seal_trace(
    tid: str,
    tokens: list[str],
    techniques: set[str] | None = None,
    indicators: set[str] | None = None,
    ts: float = 0.0,
    actor: str | None = None,
) -> Trace:
    return Trace(
        tid=tid,
        tokens=list(tokens),
        techniques=set(techniques or ()),
        indicators=set(indicators or ()),
        ts=ts,
        actor=actor,
        minhash=minhash_signature(tokens),
    )


def minhash_jaccard(a: list[int], b: list[int]) -> float:
    if not a or not b or len(a) != len(b):
        return 0.0
    return sum(x == y for x, y in zip(a, b)) / len(a)
