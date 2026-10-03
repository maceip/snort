"""Mergeable per-trace feature summary (plan section 4.2, version 1 subset).

Covers: token counts (unigrams + bigrams), 128-function MinHash over
1-3-gram shingles plus technique IDs, duration + event count, ATT&CK
technique tags, and exact indicator keys.

Every field merges in O(1) amortized per event / O(num_perm) for the
sketch, so open traces update incrementally and sealed halves combine
exactly.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Iterable, Mapping

from snort.trace.minhash import MinHashSketch

NUM_PERM = 128


def shingles_for_event(
    tokens: list[str], technique_ids: Iterable[str] = ()
) -> list[str]:
    """1-3-gram shingles of the token stream plus technique IDs."""
    shingles: list[str] = []
    n = len(tokens)
    for tok in tokens:
        shingles.append(f"u:{tok}")
    for i in range(n - 1):
        shingles.append(f"b:{tokens[i]}\x00{tokens[i + 1]}")
    for i in range(n - 2):
        shingles.append(f"t:{tokens[i]}\x00{tokens[i + 1]}\x00{tokens[i + 2]}")
    for tech in technique_ids:
        shingles.append(f"tech:{tech}")
    return shingles


def tokens_for_event(event: Mapping) -> list[str]:
    """Derive the token stream from an event dict.

    Preference: explicit ``tokens`` list, else ``template_hash``, else
    ``(action, object class)`` fallback. All values are stringified.
    """
    if isinstance(event.get("tokens"), (list, tuple)):
        return [str(t) for t in event["tokens"]]
    if event.get("template_hash") is not None:
        return [str(event["template_hash"])]
    action = str(event.get("action", ""))
    obj = event.get("object")
    if isinstance(obj, Mapping):
        obj_class = str(obj.get("class", obj.get("type", "")))
    elif obj is not None:
        obj_class = str(obj)
    else:
        obj_class = ""
    if action or obj_class:
        return [f"{action}:{obj_class}"]
    return []


def techniques_for_event(event: Mapping) -> list[str]:
    raw = event.get("technique_ids", event.get("techniques", []))
    if raw is None:
        return []
    if isinstance(raw, str):
        return [raw]
    return [str(t) for t in raw]


def indicators_for_event(event: Mapping) -> dict[str, set[str]]:
    """Normalize ``indicators`` mapping of type -> value(s) to sets of str."""
    raw = event.get("indicators", {})
    if not isinstance(raw, Mapping):
        return {}
    out: dict[str, set[str]] = {}
    for k, v in raw.items():
        key = str(k)
        if v is None:
            continue
        if isinstance(v, (list, tuple, set)):
            vals = {str(x) for x in v}
        else:
            vals = {str(v)}
        if vals:
            out.setdefault(key, set()).update(vals)
    return out


class EdgeTransitionScorer:
    """Lightweight linear edge transition scoring (PIDSMaker / VELOX)."""

    COMMON_TRANSITIONS = {
        ("process", "fork", "process"): 0.01,
        ("process", "exec", "process"): 0.05,
        ("process", "read", "file"): 0.01,
        ("process", "write", "file"): 0.02,
        ("process", "connect", "socket"): 0.05,
        ("process", "send", "socket"): 0.02,
        ("process", "recv", "socket"): 0.02,
    }

    SUSPICIOUS_TRANSITIONS = {
        ("process", "inject", "process"): 0.95,
        ("process", "write", "memory"): 0.90,
        ("process", "modify", "registry"): 0.80,
        ("process", "connect", "raw_socket"): 0.85,
        ("process", "unlink", "log"): 0.90,
    }

    def score_edge(self, subject: str, action: str, obj: str) -> float:
        s_type = "process"
        a_type = action.lower()
        o_type = "file"
        if any(w in obj.lower() for w in ("sock", ":", "http", "ip")):
            o_type = "socket"
        elif any(w in obj.lower() for w in ("proc", "pid")):
            o_type = "process"
        elif any(w in obj.lower() for w in ("mem", "shm")):
            o_type = "memory"
        elif "reg" in obj.lower():
            o_type = "registry"

        key = (s_type, a_type, o_type)
        if key in self.SUSPICIOUS_TRANSITIONS:
            return self.SUSPICIOUS_TRANSITIONS[key]
        if key in self.COMMON_TRANSITIONS:
            return self.COMMON_TRANSITIONS[key]
        return 0.25


class MergeableTraceFeatures:
    """Incrementally updated, exactly mergeable trace summary."""

    def __init__(self, num_perm: int = NUM_PERM):
        self.token_counts: Counter[str] = Counter()
        self.bigram_counts: Counter[str] = Counter()
        self.technique_tags: set[str] = set()
        self.indicators: dict[str, set[str]] = {}
        self.event_count: int = 0
        self.edge_anomaly_score: float = 0.0
        self.anomalous_edge_count: int = 0
        self.start_ts: float | None = None
        self.end_ts: float | None = None
        self.minhash = MinHashSketch(num_perm=num_perm)

    @property
    def num_perm(self) -> int:
        return self.minhash.num_perm

    @property
    def duration(self) -> float:
        if self.start_ts is None or self.end_ts is None:
            return 0.0
        return max(0.0, self.end_ts - self.start_ts)

    def add_event(
        self,
        tokens: list[str] | None = None,
        technique_ids: Iterable[str] = (),
        indicators: Mapping | None = None,
        ts: float | None = None,
        event: Mapping | None = None,
    ) -> None:
        """Add one event. Either pass parsed fields or the raw ``event`` dict."""
        if event is not None:
            tokens = tokens_for_event(event)
            technique_ids = techniques_for_event(event)
            indicators = indicators_for_event(event)
            ts = event.get("ts", ts)
        toks = list(tokens or [])
        techs = list(technique_ids or ())
        for tok in toks:
            self.token_counts[tok] += 1
        for i in range(len(toks) - 1):
            self.bigram_counts[f"{toks[i]}\x00{toks[i + 1]}"] += 1
        self.technique_tags.update(str(t) for t in techs)
        if indicators:
            if isinstance(indicators, Mapping):
                for k, v in indicators.items():
                    key = str(k)
                    if isinstance(v, str):
                        vals = {v}
                    elif isinstance(v, set):
                        vals = {str(x) for x in v}
                    else:
                        try:
                            vals = {str(x) for x in v}  # type: ignore[union-attr]
                        except TypeError:
                            vals = {str(v)}
                    if vals:
                        self.indicators.setdefault(key, set()).update(vals)
        if ts is not None:
            ts = float(ts)
            if self.start_ts is None or ts < self.start_ts:
                self.start_ts = ts
            if self.end_ts is None or ts > self.end_ts:
                self.end_ts = ts
        if event is not None and "action" in event:
            sub = str(event.get("subject", ""))
            act = str(event.get("action", ""))
            obj = str(event.get("object", ""))
            score = EdgeTransitionScorer().score_edge(sub, act, obj)
            self.edge_anomaly_score += score
            if score >= 0.7:
                self.anomalous_edge_count += 1
        self.event_count += 1
        shingles = shingles_for_event(toks, techs)
        if shingles:
            self.minhash.update(shingles)

    def merge(self, other: "MergeableTraceFeatures") -> "MergeableTraceFeatures":
        """Return a new summary equal to the union of both event streams."""
        if self.num_perm != other.num_perm:
            raise ValueError("cannot merge features with different num_perm")
        merged = MergeableTraceFeatures(num_perm=self.num_perm)
        merged.token_counts = self.token_counts + other.token_counts
        merged.bigram_counts = self.bigram_counts + other.bigram_counts
        merged.technique_tags = self.technique_tags | other.technique_tags
        merged.indicators = {k: set(v) for k, v in self.indicators.items()}
        for k, v in other.indicators.items():
            merged.indicators.setdefault(k, set()).update(v)
        merged.event_count = self.event_count + other.event_count
        merged.edge_anomaly_score = self.edge_anomaly_score + other.edge_anomaly_score
        merged.anomalous_edge_count = (
            self.anomalous_edge_count + other.anomalous_edge_count
        )
        starts = [t for t in (self.start_ts, other.start_ts) if t is not None]
        ends = [t for t in (self.end_ts, other.end_ts) if t is not None]
        merged.start_ts = min(starts) if starts else None
        merged.end_ts = max(ends) if ends else None
        merged.minhash = self.minhash.merge(other.minhash)
        return merged

    def log_token_counts(self) -> dict[str, float]:
        """log(1 + count) weights for tokens and bigrams (stage-2 baseline)."""
        out: dict[str, float] = {}
        for tok, c in self.token_counts.items():
            out[tok] = math.log1p(c)
        for bg, c in self.bigram_counts.items():
            out[f"2:{bg}"] = math.log1p(c)
        return out

    def minhash_jaccard(self, other: "MergeableTraceFeatures") -> float:
        return self.minhash.jaccard(other.minhash)

    def to_dict(self) -> dict:
        return {
            "token_counts": dict(self.token_counts),
            "bigram_counts": dict(self.bigram_counts),
            "technique_tags": sorted(self.technique_tags),
            "indicators": {k: sorted(v) for k, v in self.indicators.items()},
            "event_count": self.event_count,
            "edge_anomaly_score": round(self.edge_anomaly_score, 3),
            "anomalous_edge_count": self.anomalous_edge_count,
            "start_ts": self.start_ts,
            "end_ts": self.end_ts,
            "minhash": self.minhash.to_dict(),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "MergeableTraceFeatures":
        feats = cls(num_perm=d["minhash"]["num_perm"])
        feats.token_counts = Counter(d.get("token_counts", {}))
        feats.bigram_counts = Counter(d.get("bigram_counts", {}))
        feats.technique_tags = set(d.get("technique_tags", []))
        feats.indicators = {k: set(v) for k, v in d.get("indicators", {}).items()}
        feats.event_count = int(d.get("event_count", 0))
        feats.edge_anomaly_score = float(d.get("edge_anomaly_score", 0.0))
        feats.anomalous_edge_count = int(d.get("anomalous_edge_count", 0))
        feats.start_ts = d.get("start_ts")
        feats.end_ts = d.get("end_ts")
        feats.minhash = MinHashSketch.from_dict(d["minhash"])
        return feats

    def __eq__(self, other: object) -> bool:
        return (
            isinstance(other, MergeableTraceFeatures)
            and self.token_counts == other.token_counts
            and self.bigram_counts == other.bigram_counts
            and self.technique_tags == other.technique_tags
            and self.indicators == other.indicators
            and self.event_count == other.event_count
            and self.start_ts == other.start_ts
            and self.end_ts == other.end_ts
            and self.minhash == other.minhash
        )


import hashlib
import re


# --- Text-similarity primitives for the separability go/no-go test ---
_TOKEN = re.compile(r"[a-z0-9_]+(?:/[a-z0-9_.:-]+)?")


def tokenize(text: str) -> list[str]:
    return _TOKEN.findall((text or "").lower())


def shingles(tokens: list[str], ns: tuple[int, ...] = (1, 2, 3)) -> set[str]:
    out: set[str] = set()
    for n in ns:
        for i in range(len(tokens) - n + 1):
            out.add(" ".join(tokens[i : i + n]))
    return out


def _perm_hash(shingle: str, perm: int) -> int:
    return int.from_bytes(
        hashlib.sha256(f"{perm}\x00{shingle}".encode("utf-8")).digest()[:8], "big"
    )


def minhash_signature(shingle_set: set[str], num_perm: int = NUM_PERM) -> list[int]:
    if not shingle_set:
        return [0] * num_perm
    return [min(_perm_hash(s, p) for s in shingle_set) for p in range(num_perm)]


def minhash_jaccard(sig_a: list[int], sig_b: list[int]) -> float:
    agree = sum(1 for a, b in zip(sig_a, sig_b) if a == b)
    return agree / len(sig_a)


def trace_signatures(texts: list[str]) -> list[list[int]]:
    return [minhash_signature(shingles(tokenize(t))) for t in texts]


def tfidf_cosine(texts: list[str]):
    """Return the dense cosine-similarity matrix for trace texts."""
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.metrics.pairwise import cosine_similarity

    vec = TfidfVectorizer(
        token_pattern=r"[a-z0-9_]+(?:/[a-z0-9_.:-]+)?",
        ngram_range=(1, 2),
        sublinear_tf=True,
    )
    mat = vec.fit_transform(texts)
    return cosine_similarity(mat)


def auc(scores: list[float], labels: list[int]) -> float:
    from sklearn.metrics import roc_auc_score

    if len(set(labels)) < 2 or not scores:
        return float("nan")
    return float(roc_auc_score(labels, scores))
