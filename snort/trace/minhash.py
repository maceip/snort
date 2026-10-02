"""128-function MinHash over string shingles.

Deterministic (hashlib-based, no PYTHONHASHSEED dependence) so live runs
and replay produce identical sketches.
"""
from __future__ import annotations

import hashlib
from typing import Iterable

_DEFAULT_PERM = 128
_MAX_HASH = (1 << 64) - 1


def _hash_with_seed(shingle: str, seed: int) -> int:
    h = hashlib.sha256(f"{seed}:{shingle}".encode("utf-8")).digest()
    return int.from_bytes(h[:8], "big")


class MinHashSketch:
    """Mergeable MinHash sketch (elementwise-min merge)."""

    def __init__(self, num_perm: int = _DEFAULT_PERM, state: list[int] | None = None):
        if num_perm <= 0:
            raise ValueError("num_perm must be positive")
        self.num_perm = num_perm
        if state is None:
            self.state: list[int] = [_MAX_HASH] * num_perm
            self._empty = True
        else:
            if len(state) != num_perm:
                raise ValueError("state length must equal num_perm")
            self.state = list(state)
            self._empty = all(v == _MAX_HASH for v in self.state)

    def update(self, shingles: Iterable[str]) -> None:
        for shingle in shingles:
            for i in range(self.num_perm):
                hv = _hash_with_seed(shingle, i)
                if hv < self.state[i]:
                    self.state[i] = hv
            self._empty = False

    def merge(self, other: "MinHashSketch") -> "MinHashSketch":
        if self.num_perm != other.num_perm:
            raise ValueError("cannot merge sketches with different num_perm")
        merged = MinHashSketch(
            num_perm=self.num_perm,
            state=[min(a, b) for a, b in zip(self.state, other.state)],
        )
        merged._empty = self._empty and other._empty
        return merged

    def jaccard(self, other: "MinHashSketch") -> float:
        if self.num_perm != other.num_perm:
            raise ValueError("cannot compare sketches with different num_perm")
        if self._empty or other._empty:
            return 1.0 if self._empty and other._empty else 0.0
        agree = sum(1 for a, b in zip(self.state, other.state) if a == b)
        return agree / self.num_perm

    @property
    def is_empty(self) -> bool:
        return self._empty

    @property
    def digest(self) -> list[int]:
        return list(self.state)

    def to_dict(self) -> dict:
        return {"num_perm": self.num_perm, "state": list(self.state)}

    @classmethod
    def from_dict(cls, d: dict) -> "MinHashSketch":
        return cls(num_perm=d["num_perm"], state=list(d["state"]))

    def __len__(self) -> int:
        return self.num_perm

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, MinHashSketch)
            and self.num_perm == other.num_perm
            and self.state == other.state
        )
