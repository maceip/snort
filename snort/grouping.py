"""Overlapping groups from calibrated links (plan section 4.5 v1 subset)."""

from __future__ import annotations

from dataclasses import dataclass, field

TAU_SEED = 0.8
TAU_M = 0.5
MAX_MEMBERSHIPS = 3


@dataclass
class ScoredLink:
    a: str
    b: str
    proba: float
    n_classes: int


@dataclass
class Group:
    gid: int
    members: dict[str, float] = field(default_factory=dict)


def seed_groups(links: list[ScoredLink]) -> list[Group]:
    groups: list[Group] = []
    member_of: dict[str, set[int]] = {}
    for link in sorted(links, key=lambda l: -l.proba):
        if link.proba < TAU_SEED or link.n_classes < 2:
            continue
        ga = member_of.get(link.a, set())
        gb = member_of.get(link.b, set())
        if ga & gb:
            continue  # already share a group
        if len(ga) >= MAX_MEMBERSHIPS or len(gb) >= MAX_MEMBERSHIPS:
            continue
        gid = len(groups)
        groups.append(Group(gid=gid, members={link.a: link.proba, link.b: link.proba}))
        member_of.setdefault(link.a, set()).add(gid)
        member_of.setdefault(link.b, set()).add(gid)
    return groups


def membership_strength(
    tid: str, group: Group, link_prob: dict[tuple[str, str], float]
) -> float:
    probs = []
    for m, _ in group.members.items():
        if m == tid:
            continue
        p = link_prob.get((tid, m), link_prob.get((m, tid), 0.0))
        probs.append(float(p))
    probs.sort(reverse=True)
    top = probs[:3]
    return sum(top) / len(top) if top else 0.0


def assign_memberships(
    tids: list[str], groups: list[Group], link_prob: dict[tuple[str, str], float]
) -> tuple[dict[str, list[tuple[int, float]]], list[str]]:
    memberships: dict[str, list[tuple[int, float]]] = {}
    unassigned: list[str] = []
    for tid in tids:
        scored = []
        for g in groups:
            if tid in g.members:
                continue
            s = membership_strength(tid, g, link_prob)
            if s >= TAU_M:
                scored.append((g.gid, s))
        scored.sort(key=lambda x: -x[1])
        existing = sum(tid in group.members for group in groups)
        memberships[tid] = scored[: max(0, MAX_MEMBERSHIPS - existing)]
        in_group = any(tid in g.members for g in groups)
        if not in_group and not memberships[tid]:
            unassigned.append(tid)
    return memberships, unassigned
