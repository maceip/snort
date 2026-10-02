"""Deterministic synthetic fixtures for demo/eval.

Mimics the two v1 datasets at small scale:
- CTA-like: command sessions from N actors with distinctive vocabularies
  plus shared tooling tokens (the cross-actor confusion source), technique
  tags, indicators, and timestamps. Time-forward split: train on early
  sessions, test on late ones. Held-out actors never appear in training.
- E3-like: provenance groups with techniques/indicators but NO actor
  labels and no command text -> attribution must abstain (unresolved).
"""

from __future__ import annotations

import random

from snort.features import Trace, seal_trace

SHARED_TOOLS = ["cobalt-strike", "beacon", "mimikatz", "powershell", "rundll32"]
TECHNIQUES = [f"T10{i:02d}" for i in range(20, 32)]


def _actor_vocab(actor_idx: int) -> list[str]:
    return [f"actor{actor_idx}-tool{j}" for j in range(12)] + [
        f"cmd-word{j}" for j in range(6)
    ]


def make_cta_like(
    seed: int = 0,
    n_known: int = 6,
    n_heldout: int = 2,
    sessions_per_actor: int = 40,
) -> tuple[list[Trace], list[Trace], list[str], list[str]]:
    """Return (train, test, known_actors, heldout_actors)."""
    rng = random.Random(seed)
    known = [f"actor-{i}" for i in range(n_known)]
    heldout = [f"heldout-{i}" for i in range(n_heldout)]
    train: list[Trace] = []
    test: list[Trace] = []
    for idx, actor in enumerate(known + heldout):
        vocab = _actor_vocab(idx)
        techs = set(TECHNIQUES[idx : idx + 4])
        is_heldout = actor in heldout
        for s in range(sessions_per_actor):
            toks = rng.sample(vocab, 8) + rng.sample(SHARED_TOOLS, 2)
            rng.shuffle(toks)
            inds = {f"10.0.{idx}.{s % 5}", f"domain-{idx}-{s % 3}.example"}
            if rng.random() < 0.3:  # shared infrastructure across actors
                inds.add("shared-c2.example")
            ts = float(s * 3600 + idx * 100)
            t = seal_trace(
                tid=f"{actor}-s{s}",
                tokens=toks,
                techniques=set(rng.sample(sorted(techs), 2)),
                indicators=inds,
                ts=ts,
                actor=actor,
            )
            if is_heldout:
                test.append(t)  # held-out actors only appear at test time
            elif s < int(0.7 * sessions_per_actor):
                train.append(t)
            else:
                test.append(t)
    return train, test, known, heldout


def make_e3_like(seed: int = 0, n_groups: int = 3) -> list[Trace]:
    rng = random.Random(1000 + seed)
    traces: list[Trace] = []
    for g in range(n_groups):
        for m in range(4):
            toks = [f"proc-event-{g}-{rng.randint(0, 30)}" for _ in range(10)]
            traces.append(
                seal_trace(
                    tid=f"e3-g{g}-m{m}",
                    tokens=toks,
                    techniques={f"T10{20 + g:02d}", f"T10{21 + g:02d}"},
                    indicators={f"hash-e3-{g}-{m % 2}"},
                    ts=float(g * 900 + m * 60),
                    actor=None,
                )
            )
    return traces
