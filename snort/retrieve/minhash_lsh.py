"""Banded MinHash LSH in the spirit of DynaHash (plan section 4.3).

Implements the five version-1 fixes over the upstream defects:
1. band/table count is computed from theta, not hardcoded for theta = 0.5;
2. the record ID is stored separately from the blocking content;
3. input is a token shingle set, not character 2-grams;
4. new bucket keys are inserted into the probe tables on write;
5. the signature store is bounded (oldest entries evicted).
"""

from __future__ import annotations

import hashlib
from collections import OrderedDict

from snort.trace.signatures import minhash_jaccard
from third_party.dynahash.bktree import BKTree


def bands_for_threshold(num_perm: int, theta: float) -> tuple[int, int]:
    """Pick (bands, rows) with bands*rows == num_perm minimizing |t - theta|.

    A band of r rows over b bands fires with threshold ~(1/b)^(1/r).
    """
    if not 0.0 < theta < 1.0:
        raise ValueError("theta must be in (0, 1)")
    best: tuple[int, int] | None = None
    best_gap = float("inf")
    for rows in range(1, num_perm + 1):
        if num_perm % rows != 0:
            continue
        bands = num_perm // rows
        approx = (1.0 / bands) ** (1.0 / rows)
        gap = abs(approx - theta)
        if gap < best_gap:
            best_gap = gap
            best = (bands, rows)
    assert best is not None
    return best


def _band_key(band: tuple[int, ...]) -> str:
    raw = ",".join(str(v) for v in band).encode("ascii")
    return hashlib.blake2b(raw, digest_size=16).hexdigest()


class MinHashLSHIndex:
    """In-memory banded LSH over MinHash signatures with BK-tree multi-probe (DynaHash)."""

    def __init__(
        self,
        num_perm: int = 128,
        theta: float = 0.5,
        max_vectors: int = 1_000_000,
        seed: int = 0,
        multi_probe: bool = True,
    ) -> None:
        if max_vectors < 1:
            raise ValueError("max_vectors must be positive")
        self.num_perm = num_perm
        self.theta = theta
        self.bands, self.rows = bands_for_threshold(num_perm, theta)
        self.max_vectors = max_vectors
        self.seed = seed
        self.multi_probe = multi_probe
        # Fix 4: plain dict tables accept new keys at any time (no static tree).
        self._tables: list[dict[str, set[str]]] = [{} for _ in range(self.bands)]
        # Multi-probe BK-trees over component strings
        self._trees: list[BKTree] = [BKTree(iter([])) for _ in range(self.bands)]
        # Fix 5: bounded signature store. Fix 2: id -> signature mapping.
        self._signatures: OrderedDict[str, tuple[int, ...]] = OrderedDict()

    def __len__(self) -> int:
        return len(self._signatures)

    def insert(self, trace_id: str, signature: tuple[int, ...]) -> None:
        if len(signature) != self.num_perm:
            raise ValueError("signature length does not match num_perm")
        if trace_id in self._signatures:
            self._remove_from_tables(trace_id)
            del self._signatures[trace_id]
        elif len(self._signatures) >= self.max_vectors:
            oldest = next(iter(self._signatures))
            self._remove_from_tables(oldest)
            del self._signatures[oldest]
        self._signatures[trace_id] = signature
        for b in range(self.bands):
            band = signature[b * self.rows : (b + 1) * self.rows]
            key = _band_key(band)
            self._tables[b].setdefault(key, set()).add(trace_id)
            if self.multi_probe:
                band_str = "_".join(str(v) for v in band)
                self._trees[b].insert(band_str)

    def _remove_from_tables(self, trace_id: str) -> None:
        sig = self._signatures[trace_id]
        for b in range(self.bands):
            key = _band_key(sig[b * self.rows : (b + 1) * self.rows])
            bucket = self._tables[b].get(key)
            if bucket is not None:
                bucket.discard(trace_id)
                if not bucket:
                    del self._tables[b][key]
                    # Bucket trees retain tombstones until compaction. Bound them
                    # too, rather than letting expired streaming keys grow forever.
                    if (
                        self.multi_probe
                        and len(self._trees[b].nodes) >= 2 * self.max_vectors
                    ):
                        active = (
                            "_".join(
                                str(v)
                                for v in signature[b * self.rows : (b + 1) * self.rows]
                            )
                            for tid, signature in self._signatures.items()
                            if tid != trace_id
                        )
                        self._trees[b] = BKTree(iter(active))

    def query(
        self,
        signature: tuple[int, ...],
        exclude: str | None = None,
        probe_radius: int = 0,
    ) -> list[tuple[str, float]]:
        """Return [(trace_id, estimated Jaccard)] sorted by estimate desc."""
        if len(signature) != self.num_perm:
            raise ValueError("signature length does not match num_perm")
        hits: set[str] = set()
        for b in range(self.bands):
            band = signature[b * self.rows : (b + 1) * self.rows]
            key = _band_key(band)
            hits.update(self._tables[b].get(key, ()))

        # Adaptive multi-probe (DynaHash): If exact hits are sparse (< 5) or probe_radius > 0,
        # probe neighboring buckets within Hamming distance omega=1 in the BK-tree
        if (len(hits) < 5 or probe_radius > 0) and self.multi_probe:
            radius = max(1, probe_radius)
            for b in range(self.bands):
                band = signature[b * self.rows : (b + 1) * self.rows]
                band_str = "_".join(str(v) for v in band)
                neighbor_keys = self._trees[b].find(band_str, threshold=radius)
                for n_key in neighbor_keys:
                    n_band = tuple(int(x) for x in n_key.split("_"))
                    hits.update(self._tables[b].get(_band_key(n_band), ()))

        if exclude is not None:
            hits.discard(exclude)
        scored = [
            (tid, minhash_jaccard(signature, self._signatures[tid]))
            for tid in hits
            if tid in self._signatures
        ]
        scored.sort(key=lambda kv: (-kv[1], kv[0]))
        return scored
