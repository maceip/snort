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

RUNS

## Findings

FINDINGS

## Verdict

VERDICT

## Reproduce

```bash
./download_datasets.sh cadets_e3 && pg_restore -d cadets_e3 cadets_e3.dump     # Postgres 18
PYTHONHASHSEED=0 python pidsmaker/main.py velox CADETS_E3 --cpu --database_host localhost --artifact_dir <dir>
```
