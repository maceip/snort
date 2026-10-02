"""Candidate retrieval: banded MinHash LSH plus exact indicator index.

V1 subset of plan section 4.3: DynaHash-style LSH over MinHash with the
table count derived from theta (the shipped DynaHash defect used
``p = 1 - theta``; the paper's formula uses ``p = theta``), unioned with
an exact indicator index and capped at 50 candidates.

Ablation ``no LSH`` queries the indicator index only.
"""

from __future__ import annotations

import math
from collections import defaultdict

from snort.features import Trace, minhash_jaccard

MAX_CANDIDATES = 50


def lsh_num_tables(theta: float, k: int, delta: float = 0.1) -> int:
    """Paper formula L = ln(delta) / ln(1 - theta**k)."""
    denom = math.log(1.0 - theta**k)
    return max(1, math.ceil(math.log(delta) / denom))


class RetrievalIndex:
    def __init__(self, theta: float = 0.5, bands: int = 32, rows: int = 4) -> None:
        self.theta = theta
        self.bands = bands
        self.rows = rows
        self.tables: list[dict[tuple, set[str]]] = [
            defaultdict(set) for _ in range(bands)
        ]
        self.indicator_postings: dict[str, set[str]] = defaultdict(set)
        self.traces: dict[str, Trace] = {}
        self.insert_pos: dict[str, int] = {}

    def _band_keys(self, t: Trace):
        for b in range(self.bands):
            chunk = tuple(t.minhash[b * self.rows : (b + 1) * self.rows])
            yield b, chunk

    def insert(self, t: Trace) -> None:
        if t.tid not in self.traces:
            self.insert_pos[t.tid] = len(self.insert_pos)
        self.traces[t.tid] = t
        for b, key in self._band_keys(t):
            self.tables[b][key].add(t.tid)
        for ind in t.indicators:
            self.indicator_postings[ind].add(t.tid)

    def _lsh_hits(self, t: Trace) -> set[str]:
        hits: set[str] = set()
        for b, key in self._band_keys(t):
            hits |= self.tables[b].get(key, set())
        return hits

    def _indicator_hits(self, t: Trace) -> set[str]:
        hits: set[str] = set()
        for ind in t.indicators:
            hits |= self.indicator_postings.get(ind, set())
        return hits

    def query(self, t: Trace, mode: str = "full") -> list[str]:
        """Return up to 50 candidate tids, ranked by MinHash Jaccard.

        mode="full": LSH union indicators. mode="indicators_only": ablation.
        """
        if mode == "indicators_only":
            pool = self._indicator_hits(t)
        elif mode == "full":
            pool = self._lsh_hits(t) | self._indicator_hits(t)
        else:
            raise ValueError(f"unknown retrieval mode {mode!r}")
        pool.discard(t.tid)
        ranked = sorted(
            pool,
            key=lambda tid: minhash_jaccard(t.minhash, self.traces[tid].minhash),
            reverse=True,
        )
        return ranked[:MAX_CANDIDATES]
