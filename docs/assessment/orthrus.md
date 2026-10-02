# Assessment: ORTHRUS (ubc-provenance/orthrus) and its PIDSMaker port

The ORTHRUS repository was cloned and its detection, evaluation and reconstruction code was read. Running its reconstruction step (DepImpact) through PIDSMaker's `triage` stage on VELOX detections was attempted but did not happen (see Runs). This note records what works, what does not, and what it changes in `docs/plan.md`.

Environment: 4-core cloud container, 15 GB RAM, CPU only. `ubc-provenance/orthrus@e7f25df`, `ubc-provenance/PIDSMaker@ae1e9fd`, Postgres 18 with the E3-CADETS dump (36.5M events).

## What it is

- **Pipeline:**
  1. 15-minute provenance graphs are built from the DARPA TC Postgres database.
  2. Node features are word2vec embeddings of node text (process path and command line, file path, remote IP and port).
  3. A TGN-style encoder with graph attention feeds an edge-type-prediction decoder.
  4. A node's anomaly score is its maximum edge loss.
  5. The threshold is the maximum validation loss.
  6. DepImpact reconstruction runs from each flagged node.
- **Shipped:**
  - weights for CADETS_E3, THEIA_E3/E5 and CLEARSCOPE_E3/E5;
  - per-attack ground-truth node lists;
  - expected results, for example CADETS_E3 "full" TP 22 / FP 10, and "ano" TP 15 / FP 0.
- **Reproducibility:** the README says the original results cannot be reproduced exactly, because `PYTHONHASHSEED` was not set for word2vec.
- **PIDSMaker port:**
  - `config/orthrus.yml` is the original;
  - `config/orthrus_non_snooped.yml` removes the two practices below;
  - `config/velox.yml` is the non-snooped config with the GNN encoder replaced by a linear layer.

## Findings

1. **The original configuration uses test data twice.** PIDSMaker's own `orthrus_non_snooped.yml` and Bilot et al. both describe these practices as data snooping.
   - **Test data in features:**
     - Word2vec is trained on every node in the database, test period included.
     - Sources: `build_feature_word2vec.py` loads all of `indexid2msg`; `training_split: all` in PIDSMaker.
   - **Test data picks the operating point:**
     - **What it does:** after thresholding, `compute_kmeans_labels` takes the K highest test-node scores (K = 20 in the repo, 30 in PIDSMaker), splits them into two clusters with k-means, and flags only the higher cluster.
     - **Effect:** the alert count is chosen from the test score distribution and capped at K for the whole test period. The headline precision (CADETS_E3 "ano": 15 TP, 0 FP) is measured under that cap.
2. **Without those practices, a linear model matches it, as published.** VELOX did not reproduce here (see `pidsmaker-velox.md`). In Bilot et al. (Table 4, E3-CADETS, 5 seeds, test data excluded):

   | Model | ADP mean | ADP min | Mean precision |
   |---|---|---|---|
   | ORTHRUS | 0.94 | 0.85 | 0.66 |
   | VELOX | 0.94 | 0.77 | 0.85 |

   VELOX uses no GNN.
3. **It is unstable across seeds.** ADP ranges in Bilot et al.:

   | Dataset | ORTHRUS ADP mean | Range |
   |---|---|---|
   | E3-THEIA | 0.44 | 0.10–1.00 |
   | E3-CLEARSCOPE | 0.75 | 0.25–1.00 |
4. **How reconstruction works** (`depimpact_utils.py`, `component` mode):
   1. For each flagged node (point of interest), it loads that node's 15-minute window graph and converts it into a versioned DAG ordered by edge time.
   2. It traces backward to entry nodes and forward to exit nodes.
   3. It scores each entry or exit by the mean out/in-degree ratio of the nodes on its paths. The default is `degree`; `degree_recon` adds the normalized anomaly loss.
   4. It keeps the top-scoring entry and exit, and reports the union of their dependency nodes.
   - **No stitching across windows:** an attack that spans windows becomes one subgraph per window.
   - **Cost per flagged node:** each one rebuilds its window's DAG and scans every DAG node to find entries.

## Runs

ORTHRUS itself was not trained here; its code and configurations were read. The plan was to run DepImpact through PIDSMaker's triage stage on VELOX detections, but it did not run:
- **The options were ignored:** on `main` the `--triage.*` options were not applied, and no triage step appeared in the log.
- **No useful starting points:** the detector it would start from did not reproduce. The best VELOX run flagged at most 1 attack node among 135–180 alerts, so reconstruction would mostly have traced benign activity.
- **Not yet measured:** reconstruction quality (nodes to inspect per attack) is a Phase 0 item, run on whichever anomaly score passes the ADP check.

## Verdict

- **Kept:**
  - the DepImpact reconstruction algorithm, reimplemented over the plan's temporal graph;
  - the per-attack ground truth;
  - the evaluation rules: node-level, ADP, at least 5 seeds, no test data in features or thresholds.
- **Not used:** the GNN and the snooped configuration.
- **Plan status:**
  - **Anomaly score:** VELOX only if it reproduces; otherwise an edge-rarity score (§2.1).
  - **Reconstruction:** stitches windows by following edges across them, uses `degree_recon` scoring, and is reported with nodes-to-inspect per attack.

## Reproduce

```bash
# PIDSMaker venv (torch 1.13.1+cpu, PyG 2.5.3), Postgres with the cadets_e3 dump restored
PYTHONHASHSEED=0 python pidsmaker/main.py velox CADETS_E3 --cpu --database_host localhost --artifact_dir <dir> \
  --triage.used_method=depimpact --triage.depimpact.used_method=component --triage.depimpact.score_method=degree_recon \
  --triage.depimpact.workers=2 --triage.depimpact.visualize=False
```
