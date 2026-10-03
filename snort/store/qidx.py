"""Experimental in-memory trigram index inspired by LogLite-Q.

Filters candidates with q-gram postings and verifies a case-insensitive literal
substring. This standalone helper is not wired into the live WAL/search path.
"""

from __future__ import annotations

import collections
from typing import Iterable


def extract_trigrams(text: str) -> set[str]:
    """Extract character 3-grams from normalized text."""
    s = text.lower()
    if len(s) < 3:
        return {s} if s else set()
    return {s[i : i + 3] for i in range(len(s) - 2)}


class TrigramSidecar:
    """Postings index over character trigrams for verified literal substring search."""

    def __init__(self) -> None:
        # trigram -> list of record row indices
        self.postings: dict[str, list[int]] = collections.defaultdict(list)
        self.records: list[str] = []

    def __len__(self) -> int:
        return len(self.records)

    def add_record(self, idx: int, text: str) -> None:
        """Index one record's trigrams."""
        if idx >= len(self.records):
            self.records.extend([""] * (idx - len(self.records) + 1))
        self.records[idx] = text
        for tri in extract_trigrams(text):
            self.postings[tri].append(idx)

    def build_from_records(self, records: Iterable[str]) -> TrigramSidecar:
        for i, text in enumerate(records):
            self.add_record(i, text)
        return self

    def query(self, term: str, records: list[str] | None = None) -> list[int]:
        """Candidate filtering via trigram postings intersection + exact byte verification."""
        term_clean = term.lower()
        if not term_clean:
            return []
        rec_source = records if records is not None else self.records
        if len(term_clean) < 3:
            # Short terms bypass trigram intersection; direct verification
            return [i for i, r in enumerate(rec_source) if term_clean in r.lower()]

        trigrams = list(extract_trigrams(term_clean))
        # Start with postings of the most selective trigram (smallest list)
        sorted_trigrams = sorted(trigrams, key=lambda t: len(self.postings.get(t, [])))
        if not self.postings.get(sorted_trigrams[0]):
            return []

        candidates = set(self.postings[sorted_trigrams[0]])
        for tri in sorted_trigrams[1:]:
            candidates.intersection_update(self.postings.get(tri, []))
            if not candidates:
                return []

        # Exact byte verification (eliminates false positives from q-gram collisions)
        exact_matches = [
            idx
            for idx in sorted(candidates)
            if idx < len(rec_source) and term_clean in rec_source[idx].lower()
        ]
        return exact_matches
