# Assessment: jev-ids (jev-sec/jev-ids)

The repository was cloned and read, its test suite run, and its published comparison table recomputed from the prediction files it ships. Its main detector is a paid external API (TypeSafe's Jev), so it was not re-run. This note records what works, what does not, and what it changes in `docs/plan.md`.

Environment: 4-core cloud container, Python 3.13 via `uv`. `jev-sec/jev-ids@6aa5ac4`.

## What it is

- **Unit of analysis:** one NSL-KDD flow per request, with k labelled example flows per category in the prompt.
- **Detectors:** the Jev API, Gemini through Agno, a random forest, and an isolation forest.
- **Outputs:** a probability of attack and a category for each flow.
- **Metrics:** F1, recall on attack kinds absent from the examples, latency and cost, with McNemar tests between detectors.
- **Data:** NSL-KDD must be downloaded from Kaggle; prediction files for the paper split are shipped under `results/paper/`.

## Runs

| Run | Result |
|---|---|
| Test suite | 61 passed, 99.7% coverage |
| `jev-ids metrics` on the shipped paper predictions | reproduces the README table exactly: Jev k=1 F1 0.856, precision 0.953, recall 0.778, unseen-kind recall 0.747, 315 ms; Gemini k=1 F1 0.880; random forest k=1 F1 0.748 (recall 1.0, precision 0.598) and k=8 F1 0.865 |

## Findings

1. **Its numbers are consistent with its own predictions,** and the code is clean and well tested.
2. **The headline comparison is with a random forest trained on 5 examples (k = 1),** which labels almost everything an attack. Trained on the full pool, the README's own table gives the random forest F1 0.765 (isolation forest 0.761).
3. **It classifies single NSL-KDD flows,** a dated benchmark with no notion of traces, groups or actors. It addresses none of the six stages in this plan.
4. **The main detector cannot be run or audited offline.** Each verdict is a paid API call.

## Verdict

Not used, in any role. No code, model, prompt format, dataset (NSL-KDD), metric or evaluation method from jev-ids is part of this plan, and it is not kept as a future option or as a baseline.

**Why:**
- **Nothing to reproduce:** its detector is a closed, paid API.
- **A weak comparison:** its headline result is against a random forest trained on 5 examples.
- **The wrong task:** it classifies single flows from a dated benchmark, which none of the plan's six stages need.

Only its table was recomputed, from the prediction files it ships; the detector itself was never re-run.

## Reproduce

```bash
cd jev-ids && uv sync && uv run pytest -q
uv run jev-ids metrics results/paper/*-jev-paper results/paper/*-random_forest-paper results/paper/*gemini-paper
```
