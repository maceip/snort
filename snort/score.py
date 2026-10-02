"""Pair scoring: calibrated logistic pair model vs cosine-threshold baseline.

V1 subset of plan section 4.4/4.6 evidence: MinHash Jaccard, TF-IDF cosine,
IDF-weighted shared indicators, technique overlap, time gap. The full
model is logistic regression with isotonic calibration; the ablation is a
single cosine threshold fit on validation pairs.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression

from snort.features import Trace, minhash_jaccard


@dataclass
class Evidence:
    jaccard: float
    cosine: float
    shared_indicators: float
    technique_overlap: float
    time_gap: float  # hours, absolute

    def vector(self) -> list[float]:
        return [
            self.jaccard,
            self.cosine,
            self.shared_indicators,
            self.technique_overlap,
            -math.log1p(self.time_gap),
        ]

    def n_classes(self) -> int:
        """Independent evidence classes present (plan section 4.5 seeding)."""
        n = 0
        if self.jaccard > 0.05 or self.cosine > 0.05:
            n += 1  # behaviour sequence
        if self.technique_overlap > 0.0:
            n += 1  # technique set
        if self.shared_indicators > 0.0:
            n += 1  # infrastructure
        return n


def idf_shared(a: set[str], b: set[str], df: dict[str, int], n: int) -> float:
    shared = a & b
    if not shared:
        return 0.0
    return sum(math.log((1 + n) / (1 + df.get(k, 0))) for k in shared)


def technique_jaccard(a: set[str], b: set[str]) -> float:
    if not a and not b:
        return 0.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


class PairFeaturizer:
    def __init__(self) -> None:
        self.vectorizer = TfidfVectorizer(ngram_range=(1, 2), min_df=1)
        self.vecs = {}
        self.df: dict[str, int] = {}
        self.n = 0

    def fit(self, traces: list[Trace]) -> None:
        mat = self.vectorizer.fit_transform([t.text() for t in traces])
        for t, row in zip(traces, mat):
            self.vecs[t.tid] = row
        self.n = len(traces)
        df_counts: dict[str, int] = {}
        for t in traces:
            for ind in t.indicators:
                df_counts[ind] = df_counts.get(ind, 0) + 1
        self.df = df_counts

    def cosine(self, a: Trace, b: Trace) -> float:
        va, vb = self.vecs.get(a.tid), self.vecs.get(b.tid)
        if va is None or vb is None:
            return 0.0
        num = float(va.multiply(vb).sum())
        da = math.sqrt(float(va.multiply(va).sum()))
        db = math.sqrt(float(vb.multiply(vb).sum()))
        if da == 0.0 or db == 0.0:
            return 0.0
        return num / (da * db)

    def evidence(self, a: Trace, b: Trace) -> Evidence:
        return Evidence(
            jaccard=minhash_jaccard(a.minhash, b.minhash),
            cosine=self.cosine(a, b),
            shared_indicators=idf_shared(a.indicators, b.indicators, self.df, self.n),
            technique_overlap=technique_jaccard(a.techniques, b.techniques),
            time_gap=abs(a.ts - b.ts) / 3600.0,
        )


class PairModel:
    """Logistic regression + isotonic calibration over pair evidence."""

    def __init__(self) -> None:
        self.clf = LogisticRegression(max_iter=1000)
        self.cal: IsotonicRegression | None = None

    def fit(self, X: list[list[float]], y: list[int]) -> None:
        Xa = np.asarray(X, dtype=float)
        ya = np.asarray(y)
        self.clf.fit(Xa, ya)
        raw = self.clf.predict_proba(Xa)[:, 1]
        self.cal = IsotonicRegression(out_of_bounds="clip").fit(raw, ya)

    def predict_proba(self, X: list[list[float]]) -> np.ndarray:
        raw = self.clf.predict_proba(np.asarray(X, dtype=float))[:, 1]
        assert self.cal is not None
        return self.cal.predict(raw)


class CosineBaseline:
    """Ablation: single cosine threshold instead of the pair model."""

    def __init__(self, threshold: float = 0.5) -> None:
        self.threshold = threshold

    def fit(self, cosines: list[float], y: list[int]) -> None:
        best_t, best_acc = 0.5, -1.0
        for t in sorted(set(cosines)):
            acc = sum((1 if c >= t else 0) == v for c, v in zip(cosines, y)) / len(y)
            if acc > best_acc:
                best_t, best_acc = t, acc
        self.threshold = best_t

    def predict_proba(self, cosines: list[float]) -> list[float]:
        return [0.9 if c >= self.threshold else 0.1 for c in cosines]
