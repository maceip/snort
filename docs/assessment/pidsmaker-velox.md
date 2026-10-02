# Assessment: PIDSMaker and VELOX (ubc-provenance/PIDSMaker)

PIDSMaker was cloned and read. The DARPA E3-CADETS database was restored from the published dump, and VELOX, the simple detector from Bilot et al. ("Sometimes Simpler is Better"), was run through PIDSMaker's own pipeline on a CPU. This note records what works, what does not, and what it changes in `docs/plan.md`.

Environment: 4-core cloud container, 15 GB RAM, CPU only, Python 3.10 venv (torch 1.13.1+cpu, PyG 2.5.3), Postgres 18. `ubc-provenance/PIDSMaker@ae1e9fd`.

## What it is

- **A framework of eight provenance detectors** (Kairos, Flash, Magic, NodLink, ThreaTrace, R-Caid, ORTHRUS, VELOX), each defined in YAML over a shared pipeline. The pipeline stages are construction, transformation, featurization, feature inference, batching, training, evaluation, and an optional triage step (ORTHRUS's DepImpact or OCR-APT's subgraph step).
- **VELOX** (`config/velox.yml`):
  - **Inputs:** word2vec node embeddings trained on the training split only.
  - **Model:** one linear layer instead of a GNN encoder, and an edge-type-prediction decoder.
  - **Scoring:** a node's score is its maximum edge loss; the threshold is the maximum validation loss.
  - **Speed:** it scores one edge at a time from its two endpoint embeddings, so it can run in real time.
- **Published results (Bilot et al., Table 4, E3-CADETS, 5 seeds):** ADP mean 0.94, min 0.77, best 1.00; mean precision 0.85.
- **Data:** the DARPA TC databases are published as Postgres dumps (`download_datasets.sh`, Google Drive). E3-CADETS is 1.47 GB compressed, 36.5M events and about 11 GB once restored.
- **The README's own warning:** results vary substantially across seeds, and reproducing them as the framework evolves "presents a real challenge".

## Setup problems

| Problem | Fix |
|---|---|
| The dump is pg_dump format 1.16, which Postgres 16 cannot read | Postgres 18 from PGDG |
| `--tuned` loads `config/tuned_baselines/cadets_e3/tuned_velox.yml`, which is missing | Default `velox.yml` |
| Restoring wrote more than 4 GB of WAL and filled the disk | `max_wal_size=256MB` on the command line (it overrides `ALTER SYSTEM`) |
| Graph construction was killed when it shared 15 GB with another job | Run alone |

## Runs

| Run | Settings | Best ADP | Best-epoch TP / FP | Time |
|---|---|---|---|---|
| Published (Bilot et al., Table 4) | tuned, 5 seeds, GPU | 0.94 mean, 0.77 min | 8 / 0 (best seed) | — |
| 1 | default `velox.yml`, seed 0 | killed out of memory at 13.6 GB when training started | — | — |
| 2 | default `velox.yml` (embeddings 128, hidden 128), seed 0, memory patch | **0.008** | 1 / 134 | graphs 4 min, word2vec 20 s, features 3.5 min, 12 epochs about 20 min, evaluation 7 min |
| 3 | `main`, the tuned settings from `docs/docs/tuned_systems.md` except embeddings (hidden and output 256, lr 1e-4, dropout 0.3, embeddings kept at 128) | **0.007** | 1 / 180 | about 4.5 min per epoch |
| 4 | the paper's own `velox` branch (`54f687c`) with `--tuned`, which loads `tuned_baselines/cadets_e3/tuned_velox.yml` (embeddings 64, seed 69, lr 1e-3, output 256) | running | — | |

- **Settings `main` lists:** `docs/docs/tuned_systems.md` gives embeddings 256, lr 1e-4 and hidden 256. That would double the 6.1 GB of edge features and the training memory, which does not fit this container.
- **Settings the paper used:** the paper links the `velox` branch, not `main`. That branch ships the `tuned_velox.yml` that `main` lacks, with embeddings 64, seed 69, lr 1e-3 and output 256, and a comment recording "ADP@1.00".
- **So the two disagree:** the settings `main` documents do not match the configuration that produced the published result.

Run 2 detail:
- Ground truth loads correctly: 72 of 72 attack nodes are found in 9 test windows.
- At the best epoch, attack nodes have losses of 3.7–8. The threshold, the maximum validation loss, is 15.9.
- Many benign nodes score higher than the attack nodes, so the ranking itself fails, not only the threshold.

## Findings

1. **The pipeline did not fit in 15 GB.** The training loader keeps train, val and test edge features in memory and then concatenates them into a second full copy (`get_full_data`). Only the TGN last-neighbour loader uses that copy, and VELOX does not use that loader. The first run was killed at 13.6 GB. A two-line patch skips the copy when that loader is off; it does not change results.

## Verdict

Pending the ADP result.

## Reproduce

```bash
./download_datasets.sh cadets_e3 && pg_restore -d cadets_e3 cadets_e3.dump     # Postgres 18
PYTHONHASHSEED=0 python pidsmaker/main.py velox CADETS_E3 --cpu --database_host localhost --artifact_dir <dir>
```
