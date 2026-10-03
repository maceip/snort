"""Overlapping group memberships from calibrated pair links.

Implements plan section 4.5 (membership rules) and the version-1 subset
(section "Version 1 builds", stage 5):

- ``s(t, g)`` is the mean of the top-3 calibrated link probabilities
  between trace ``t`` and members of group ``g``, blended with prototype
  similarity.
- A trace keeps up to three memberships with ``s >= tau_m`` (default 0.5).
  Otherwise it stays unassigned but remains indexed.
- A pair with ``p >= tau_seed`` (default 0.8) and at least two evidence
  classes seeds a new group when the two traces share no group yet. Either
  trace may already belong to other groups (overlap, never transitive
  closure).
- Membership states: proposed -> supported -> analyst-confirmed /
  analyst-rejected. Analyst decisions are stored as trace-group labels and
  are never expanded into pair labels.
- Automatic memberships become unsupported when current evidence falls below
  the assignment threshold; their history is retained without an active slot.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Mapping, Optional, Sequence, Tuple

# Blend weight for prototype similarity in s(t, g).
_PROTOTYPE_WEIGHT = 0.3
# A shared member with strength at or above this counts for merge proposals.
STRONG_MEMBER = 0.7

VALID_STATES = (
    "proposed",
    "supported",
    "unsupported",
    "analyst-confirmed",
    "analyst-rejected",
)


@dataclass(frozen=True)
class ScoredLink:
    """One calibrated pair decision between a candidate trace and a member."""

    other_trace_id: str
    probability: float
    evidence_classes: Tuple[str, ...] = ()
    contributions: Mapping[str, float] = field(default_factory=dict)
    shared_shingles: Tuple[str, ...] = ()
    shared_indicators: Tuple[str, ...] = ()
    event_hashes: Tuple[str, ...] = ()


@dataclass
class Membership:
    """One trace's membership in one group, with its evidence."""

    trace_id: str
    group_id: str
    strength: float
    state: str = "proposed"
    evidence: Dict = field(default_factory=dict)
    version: int = 1

    @property
    def active(self) -> bool:
        return self.state not in ("unsupported", "analyst-rejected")


@dataclass
class Group:
    """An overlapping group of traces."""

    group_id: str
    members: Dict[str, Membership] = field(default_factory=dict)
    version: int = 1


def membership_strength(
    link_probs: Sequence[float],
    prototype_similarity: Optional[float] = None,
) -> float:
    """Compute s(t, g): mean of top-3 link probabilities, blended with prototype.

    When ``prototype_similarity`` is None the strength is the plain mean of
    the top-3 probabilities (over whatever links exist, 1-3).
    Otherwise ``s = 0.7 * mean_top3 + 0.3 * prototype_similarity``.
    Empty input returns 0.0.
    """
    if not link_probs:
        return 0.0
    top = sorted(link_probs, reverse=True)[:3]
    mean_top3 = sum(top) / len(top)
    if prototype_similarity is None:
        return float(mean_top3)
    return float(
        (1.0 - _PROTOTYPE_WEIGHT) * mean_top3 + _PROTOTYPE_WEIGHT * prototype_similarity
    )


def build_membership_evidence(links: Sequence[ScoredLink]) -> Dict:
    """Build per-membership evidence from the links to group members.

    Returns top evidence contributions (summed per class, descending),
    plus shared shingles / indicators with event-hash pointers.
    """
    summed: Dict[str, float] = {}
    shingles: Dict[str, None] = {}
    indicators: Dict[str, None] = {}
    event_hashes: Dict[str, None] = {}
    for link in links:
        for cls, value in dict(link.contributions).items():
            summed[cls] = summed.get(cls, 0.0) + float(value)
        for s in link.shared_shingles:
            shingles[s] = None
        for ind in link.shared_indicators:
            indicators[ind] = None
        for h in link.event_hashes:
            event_hashes[h] = None
    top_contributions = sorted(summed.items(), key=lambda kv: kv[1], reverse=True)
    return {
        "top_contributions": top_contributions,
        "shared_shingles": sorted(shingles),
        "shared_indicators": sorted(indicators),
        "event_hashes": sorted(event_hashes),
        "n_links": len(links),
    }


class GroupManager:
    """Owns overlapping groups. Single writer; no locks needed (plan section 3)."""

    def __init__(
        self,
        tau_m: float = 0.5,
        tau_seed: float = 0.8,
        max_memberships: int = 3,
    ) -> None:
        self.tau_m = tau_m
        self.tau_seed = tau_seed
        self.max_memberships = max_memberships
        self.groups: Dict[str, Group] = {}
        self._next_group = 1
        # Analyst trace-group labels: (trace_id, group_id) -> decision.
        self.analyst_labels: Dict[Tuple[str, str], str] = {}

    # -- queries ---------------------------------------------------------
    def groups_of(self, trace_id: str) -> List[str]:
        return [
            gid
            for gid, g in self.groups.items()
            if trace_id in g.members and g.members[trace_id].active
        ]

    def shared_groups(self, trace_a: str, trace_b: str) -> List[str]:
        return [
            gid for gid in self.groups_of(trace_a) if gid in self.groups_of(trace_b)
        ]

    # -- scoring ---------------------------------------------------------
    def score_trace(
        self,
        trace_id: str,
        links_by_group: Mapping[str, Sequence[ScoredLink]],
        prototype_by_group: Optional[Mapping[str, float]] = None,
    ) -> List[Tuple[str, float, Dict]]:
        """Score one trace against candidate groups.

        Returns ``[(group_id, strength, evidence)]`` for groups with
        ``s >= tau_m``, sorted by strength descending, capped at
        ``max_memberships``. Empty list means unassigned (stays indexed).
        """
        prototype_by_group = prototype_by_group or {}
        scored: List[Tuple[str, float, Dict]] = []
        for group_id, links in links_by_group.items():
            if group_id not in self.groups:
                continue
            member = self.groups[group_id].members.get(trace_id)
            if member is not None and member.state == "analyst-rejected":
                continue
            probs = [link.probability for link in links]
            proto = prototype_by_group.get(group_id)
            strength = membership_strength(probs, proto)
            if strength >= self.tau_m and probs:
                scored.append(
                    (group_id, strength, build_membership_evidence(list(links)))
                )
        scored.sort(key=lambda item: item[1], reverse=True)
        return scored[: self.max_memberships]

    def assign(
        self,
        trace_id: str,
        links_by_group: Mapping[str, Sequence[ScoredLink]],
        prototype_by_group: Optional[Mapping[str, float]] = None,
    ) -> List[Membership]:
        """Refresh current support, retaining analyst labels and inactive history."""
        prototype_by_group = prototype_by_group or {}
        out: List[Membership] = []
        # Refresh existing memberships even if their new score is below tau_m.
        # Missing/empty current evidence is not permission to keep an old score.
        for group_id, links in links_by_group.items():
            group = self.groups.get(group_id)
            existing = group.members.get(trace_id) if group else None
            if existing is None or existing.state == "analyst-rejected":
                continue
            strength = membership_strength(
                [link.probability for link in links], prototype_by_group.get(group_id)
            )
            if existing.state != "analyst-confirmed":
                has_slot = (
                    existing.active
                    or len(self.groups_of(trace_id)) < self.max_memberships
                )
                existing.state = (
                    ("supported" if strength >= self.tau_seed else "proposed")
                    if links and strength >= self.tau_m and has_slot
                    else "unsupported"
                )
            existing.strength = strength
            existing.evidence = build_membership_evidence(list(links))
            existing.version += 1
            group.version += 1
            out.append(existing)
        scored = self.score_trace(trace_id, links_by_group, prototype_by_group)
        for group_id, strength, evidence in scored:
            group = self.groups[group_id]
            existing = group.members.get(trace_id)
            if existing is not None:
                continue  # Already refreshed, including inactive/capped memberships.
            else:
                if len(self.groups_of(trace_id)) >= self.max_memberships:
                    continue
                membership = Membership(
                    trace_id=trace_id,
                    group_id=group_id,
                    strength=strength,
                    state="supported" if strength >= self.tau_seed else "proposed",
                    evidence=evidence,
                )
                group.members[trace_id] = membership
                group.version += 1
                out.append(membership)
        return out

    # -- seeding ---------------------------------------------------------
    def maybe_seed(
        self,
        trace_a: str,
        trace_b: str,
        probability: float,
        evidence_classes: Sequence[str],
        evidence: Optional[Dict] = None,
    ) -> Optional[str]:
        """Seed a group from a strong pair. Returns the new group id or None.

        Seeds only when ``probability >= tau_seed``, at least two evidence
        classes support the link, and the traces share no group yet. Either
        trace may already belong to other groups (overlap).
        """
        if probability < self.tau_seed:
            return None
        if len(set(evidence_classes)) < 2:
            return None
        if self.shared_groups(trace_a, trace_b):
            return None
        if any(
            all(
                t in group.members and group.members[t].state != "analyst-rejected"
                for t in (trace_a, trace_b)
            )
            for group in self.groups.values()
        ):
            return None  # Reactivate the historical group rather than duplicating it.
        if any(
            len(self.groups_of(tid)) >= self.max_memberships
            for tid in (trace_a, trace_b)
        ):
            return None
        group_id = f"g{self._next_group}"
        self._next_group += 1
        group = Group(group_id=group_id)
        base_evidence = dict(evidence or {})
        base_evidence.setdefault("seed_probability", probability)
        base_evidence.setdefault("seed_evidence_classes", sorted(set(evidence_classes)))
        for trace_id in (trace_a, trace_b):
            group.members[trace_id] = Membership(
                trace_id=trace_id,
                group_id=group_id,
                strength=float(probability),
                state="proposed",
                evidence=dict(base_evidence),
            )
        self.groups[group_id] = group
        return group_id

    # -- analyst labels --------------------------------------------------
    def analyst_decide(self, trace_id: str, group_id: str, decision: str) -> Membership:
        """Record an analyst decision as a trace-group label (never a pair label)."""
        if decision not in ("analyst-confirmed", "analyst-rejected"):
            raise ValueError(f"unknown analyst decision: {decision!r}")
        group = self.groups[group_id]
        membership = group.members[trace_id]
        if (
            decision == "analyst-confirmed"
            and not membership.active
            and len(self.groups_of(trace_id)) >= self.max_memberships
        ):
            raise ValueError("trace already has the maximum active memberships")
        membership.state = decision
        membership.version += 1
        group.version += 1
        self.analyst_labels[(trace_id, group_id)] = decision
        return membership

    # -- merge proposals -------------------------------------------------
    def merge_proposals(self) -> List[Tuple[str, str, List[str]]]:
        """Propose online merges: group pairs sharing strong members.

        Returns ``[(group_a, group_b, shared_trace_ids)]`` for pairs sharing
        at least one member with strength >= 0.7 in both groups. Proposals
        only; callers record the decision in the ledger, never auto-merge
        (no transitive closure).
        """
        proposals: List[Tuple[str, str, List[str]]] = []
        group_ids = sorted(self.groups)
        for i, gid_a in enumerate(group_ids):
            for gid_b in group_ids[i + 1 :]:
                shared = [
                    tid
                    for tid, m in self.groups[gid_a].members.items()
                    if tid in self.groups[gid_b].members
                    and m.active
                    and self.groups[gid_b].members[tid].active
                    and m.strength >= STRONG_MEMBER
                    and self.groups[gid_b].members[tid].strength >= STRONG_MEMBER
                ]
                if shared:
                    proposals.append((gid_a, gid_b, sorted(shared)))
        return proposals

    def group_timeline(
        self, group_id: str, trace_spans: Mapping[str, Tuple[float, float]]
    ) -> List[Tuple[str, float, float]]:
        """Timeline across active members, sorted by start."""
        group = self.groups[group_id]
        spans = [
            (tid, *trace_spans[tid])
            for tid, member in group.members.items()
            if member.active and tid in trace_spans
        ]
        spans.sort(key=lambda item: (item[1], item[0]))
        return spans
