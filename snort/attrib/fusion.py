"""Attribution fusion against an explicit unknown actor (plan section 4.6).

Evidence classes by observation source:
- execution content: TF-IDF + logistic regression over group command
  traces PLUS IDF-weighted technique overlap, stacked into ONE jointly
  calibrated score (one class);
- infrastructure / artifacts: fixed capped priors until the emulation lab
  supplies labelled data (v1: absent -> weight 0).

Fusion is a sum of calibrated log-likelihood ratios, one term per class,
scored against an explicit unknown-actor hypothesis with its own prior.
Decision (posteriors over actors + unknown):
- attributed: posterior >= 0.9 AND >= 2 independent classes AND robust to
  leave-one-class-out. Implemented but UNREACHABLE in v1: command-only
  traces (the whole CTA corpus) are capped at candidates, per plan.
- candidates: top known posterior >= 0.3;
- unresolved: otherwise.
Held-out CTA actors and labelless E3 groups must come out unresolved.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from snort.score import technique_jaccard

CANDIDATE_THRESHOLD = 0.3
ATTRIBUTED_THRESHOLD = 0.9
UNKNOWN_PRIOR = 0.3
EXEC_CLF_WEIGHT = 0.7
EXEC_TECH_WEIGHT = 0.3
_EPS = 1e-6


def _logit(p: float) -> float:
    p = min(max(p, _EPS), 1.0 - _EPS)
    return math.log(p / (1.0 - p))


@dataclass
class AttributionResult:
    group_id: str
    ranking: list[tuple[str, float]]  # known actors, posterior desc
    unknown_posterior: float
    decision: str  # "candidates" | "unresolved" ("attributed" off in v1)
    n_evidence_classes: int
    evidence: dict = field(default_factory=dict)


class ActorAttributor:
    """TF-IDF + LR classifier fused with technique overlap vs unknown."""

    def __init__(self) -> None:
        self.vectorizer = TfidfVectorizer(ngram_range=(1, 2), min_df=1)
        self.clf = LogisticRegression(max_iter=1000)
        self.actors: list[str] = []
        self.tech_profiles: dict[str, set[str]] = {}
        self.tech_idf: dict[str, float] = {}
        self.model_hash_ctx: dict = {}

    def fit(
        self, texts: list[str], actors: list[str], techniques: list[set[str]]
    ) -> None:
        if len(set(actors)) < 2:
            raise ValueError("need >= 2 actors to fit the attribution classifier")
        X = self.vectorizer.fit_transform(texts)
        self.clf.fit(X, actors)
        self.actors = sorted(set(actors))
        profiles: dict[str, set[str]] = {a: set() for a in self.actors}
        for a, techs in zip(actors, techniques):
            profiles[a] |= set(techs)
        self.tech_profiles = profiles
        df: dict[str, int] = {}
        for techs in profiles.values():
            for t in techs:
                df[t] = df.get(t, 0) + 1
        n = len(profiles)
        self.tech_idf = {t: math.log((1 + n) / (1 + c)) for t, c in df.items()}
        self.model_hash_ctx = {
            "vocab": len(self.vectorizer.vocabulary_),
            "actors": self.actors,
            "clf": "tfidf-lr-1-2gram",
        }

    def _tech_score(self, techs: set[str], actor: str) -> float:
        profile = self.tech_profiles.get(actor, set())
        if not techs or not profile:
            return 0.0
        plain = technique_jaccard(techs, profile)
        inter = techs & profile
        if not inter:
            return 0.0
        w_inter = sum(self.tech_idf.get(t, 0.0) for t in inter)
        w_union = sum(self.tech_idf.get(t, 0.0) for t in (techs | profile)) or 1.0
        return 0.5 * plain + 0.5 * (w_inter / w_union)

    def _exec_scores(self, text: str, techs: set[str]) -> dict[str, float]:
        proba = self.clf.predict_proba(self.vectorizer.transform([text]))[0]
        clf_p = dict(zip(self.clf.classes_, proba))
        return {
            a: EXEC_CLF_WEIGHT * float(clf_p.get(a, 0.0))
            + EXEC_TECH_WEIGHT * self._tech_score(techs, a)
            for a in self.actors
        }

    def attribute_group(
        self,
        group_id: str,
        texts: list[str],
        techniques: set[str],
        has_multiclass_evidence: bool = False,
    ) -> AttributionResult:
        """Fuse one group's command traces against actors + unknown.

        Group text is the concatenation of member command traces. Empty
        groups (no command content, e.g. E3 provenance groups) carry no
        execution evidence and come out unresolved.
        """
        if not texts or not any(t.strip() for t in texts):
            return AttributionResult(
                group_id=group_id,
                ranking=[(a, 0.0) for a in self.actors],
                unknown_posterior=1.0,
                decision="unresolved",
                n_evidence_classes=0,
                evidence={"reason": "no-command-content"},
            )
        joined = "\n".join(texts)
        exec_scores = self._exec_scores(joined, techniques)
        n_actors = len(self.actors)
        prior_known = (1.0 - UNKNOWN_PRIOR) / max(n_actors, 1)
        logits = {a: _logit(s) + math.log(prior_known / UNKNOWN_PRIOR) for a, s in exec_scores.items()}
        logits["__unknown__"] = 0.0
        mx = max(logits.values())
        exps = {k: math.exp(v - mx) for k, v in logits.items()}
        total = sum(exps.values())
        post = {k: v / total for k, v in exps.items()}
        unk = post.pop("__unknown__")
        ranking = sorted(post.items(), key=lambda kv: -kv[1])
        top_actor, top_p = ranking[0]
        evidence = {
            "exec_scores": {k: round(v, 4) for k, v in exec_scores.items()},
            "posteriors": {k: round(v, 4) for k, v in post.items()},
            "unknown": round(unk, 4),
            "top": top_actor,
        }
        # v1 cap: command-only input has one evidence class -> never attributed.
        n_classes = 1 + (1 if has_multiclass_evidence else 0)
        if top_p >= ATTRIBUTED_THRESHOLD and n_classes >= 2 and has_multiclass_evidence:
            decision = "attributed"
        elif top_p >= CANDIDATE_THRESHOLD:
            decision = "candidates"
        else:
            decision = "unresolved"
        return AttributionResult(
            group_id=group_id,
            ranking=[(a, round(p, 4)) for a, p in ranking],
            unknown_posterior=round(unk, 4),
            decision=decision,
            n_evidence_classes=1,
            evidence=evidence,
        )
