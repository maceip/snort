"""Time-forward and open-set split helpers (plan sec 7.2).

Rules enforced here, not by convention at each call site:
- time-forward: test items are strictly newer than train items;
- group-aware: no session / beacon / incident appears on both sides;
- open-set: held-out actors are disjoint across validation and test.
"""

from __future__ import annotations

import hashlib


def time_forward_split(
    items: list[dict], time_key: str, group_key: str, test_frac: float = 0.15,
    val_frac: float = 0.15,
) -> dict:
    """Split whole groups ordered by each group's earliest timestamp.

    Returns {"train": [...], "val": [...], "test": [...], "cut_val": ts,
    "cut_test": ts} where the lists hold group ids. Latest groups go to test.
    """
    if not 0 < test_frac < 1 or not 0 <= val_frac < 1 or test_frac + val_frac >= 1:
        raise ValueError("test_frac/val_frac must satisfy 0 <= val, 0 < test, sum < 1")
    first_ts: dict = {}
    for it in items:
        g = it[group_key]
        t = int(it[time_key])
        if g not in first_ts or t < first_ts[g]:
            first_ts[g] = t
    ordered = sorted(first_ts, key=lambda g: (first_ts[g], str(g)))
    n = len(ordered)
    n_test = max(1, round(n * test_frac)) if n >= 3 else (1 if n == 2 else 0)
    n_val = max(1, round(n * val_frac)) if n - n_test >= 3 else 0
    test = ordered[n - n_test :] if n_test else []
    val = ordered[n - n_test - n_val : n - n_test] if n_val else []
    train = ordered[: n - n_test - n_val]
    return {
        "train": train,
        "val": val,
        "test": test,
        "cut_val": first_ts[val[0]] if val else None,
        "cut_test": first_ts[test[0]] if test else None,
    }


def open_set_actor_split(
    actors: list[str], holdout_frac: float = 0.2, seed: int = 42
) -> dict:
    """Hold out whole actors; the held-out set is split disjointly in two."""
    if not 0 < holdout_frac < 1:
        raise ValueError("holdout_frac must be in (0, 1)")
    ordered = sorted(set(actors))
    n_hold = max(1, round(len(ordered) * holdout_frac)) if len(ordered) >= 2 else 0
    digest = hashlib.sha256(f"open-set:{seed}".encode()).digest()
    keyed = sorted(
        ordered,
        key=lambda a: hashlib.sha256(digest + a.encode()).hexdigest(),
    )
    held = keyed[:n_hold]
    kept = sorted(set(ordered) - set(held))
    mid = len(held) // 2
    return {
        "kept": kept,
        "open_val_actors": sorted(held[:mid]),
        "open_test_actors": sorted(held[mid:]),
        "seed": seed,
    }
