# Assessment: DynaHash and PER-Design-Space-Exploration

Both repositories were cloned, read in full and run on their own bundled data. This note records what works, what does not, and what it changes in `docs/plan.md`.

Environment: 4-core cloud container, Python 3.12 venv. Repos at `dimkar121/DynaHash@14fbaa9` and `JacobMaciejewski/PER-Design-Space-Exploration@09eeb4a`. pyJedAI 0.3.6 from PyPI. All times are from this container and only indicate relative cost.

## DynaHash

### What it is
- About 360 lines in `DynaHash.py`: MinHash over character 2-grams (mmh3, m = 116), Hamming LSH with L hash tables of k = 6 sampled components, in-memory buckets (`add`/`get`), RocksDB-backed buckets (`db_add`/`db_get`), ranked retrieval (`get_ranks`) and multi-probe via BK-trees (`probe_get`).
- The bounded in-memory summary T from the paper is not in the library. It exists only as module-level globals in the demo script `main_db_T.py`.

### Runs

| Run | Result |
|---|---|
| `main_ACM_DBLP.py` | recall 0.99, precision 0.69 (2,197 TP, 998 FP), 16 s |
| `main_Scholar_DBLP.py` | recall 0.96, precision 0.15 (5,120 TP, 28,046 FP), 3 min 6 s |
| `main_probe.py` (ω = 1, 2,209 names) | L_ω = 48 instead of L = 147; recall 0.99 and precision 1.00 against brute-force MinHash neighbours; 2.4 blocks per table; 38 ms per query |
| In-memory insert, 50k DBLP names | about 1,000 records/s |
| In-memory query (34k stored) | 1.3 ms, 64 candidates |
| RocksDB insert, 10k names | about 540 records/s |
| RocksDB query | 8.2 ms |

The recall figures match the paper's claims for these datasets. Precision on Scholar–DBLP is low (0.15) because candidates are not verified beyond the Hamming threshold. The multi-probe numbers match the paper's L_ω = 48 and roughly 3 blocks per table. That recall is measured against MinHash-space neighbours, not true matches.

### Defects found

1. **Hash-table count is wrong for any θ ≠ 0.5.** `DynaHash.py:25` sets `p = 1 - self.th` and line 26 computes L = ln δ / ln(1 − p^k). The paper's formula, and the code's own `get_ranks`, use p = θ. The two agree only at the default θ = 0.5.

   | θ | L built by the code | L required by the paper's formula |
   |---|---|---|
   | 0.5 | 147 | 147 |
   | 0.6 | 562 | 49 |
   | 0.7 | 3,158 | 19 |
   | 0.8 | 35,977 | 8 |

   Above 0.5 the code wastes memory and time; below 0.5 it builds too few tables to meet the stated recall guarantee. The paper's Abt–Buy run used θ = 0.45 and δ = 0.001: the code would build 246 tables where 829 are required. That script is not in the repo, so what was actually run can't be confirmed. `main_db_T.py:11` repeats the same `p = 1 - t`.
2. **Records with the same key collapse into one.** `add(key, v)` uses the string as both the blocking key and the record identity (`self.vs[key] = …`, line 252). Of 50,000 DBLP names inserted, 34,411 entries remain, and two records with the same string return only the last value. Identical traces are common in telemetry, so this would silently drop trace IDs.
3. **Memory of T is not bounded.** `main_db_T.py` keeps every record's 116-value MinHash vector in a global dict `A` (line 80), and only the bucket lists are capped at w with random eviction (line 92). The paper's bounded-memory property holds for bucket slots, not for the stored vectors.
4. **Multi-probe is batch-only.** BK-trees are built once in `finalize()` (line 78) from the keys present at that moment. Blocks created by later `add` calls are invisible to probing, so multi-probe does not work on a stream without rebuilding.
5. **Input and parameters are fixed.** MinHash input is always a string's character 2-grams (`str_to_MinHash(key, 2, j)` at every call site). The constructor's `q` and `eps` arguments are ignored, and m = 116 is hard-coded at line 23. Token sets such as trace shingles need a different input path.
6. **Packaging.** The RocksDB binding is imported as `rocksdbpy`, but the PyPI package is `rocksdb-py`, and it is missing from `requirements.txt` (which is UTF-16 encoded). As documented, the persistent mode does not install.

### Verdict
The core idea reproduces and the code is small enough to own. It is usable as the reference implementation for stage 3 only after fixing 1, 2, 4 and 5, plus a bounded vector store for 3. Insert throughput of about 1,000/s in Python covers a replay demo at roughly 1,000 sealed traces/s, but not the 100k events/s ingest target if every trace is indexed. A compiled port is justified only once the fixed Python version has been measured on trace data.

## PER-Design-Space-Exploration

### What it is
- A 244-line runner (`run_workflow_setup.py`), 17 grid-config JSON files and wrappers for DeepBlocker and Sparkly. Every algorithm lives in pyJedAI (`pyjedai.prioritization`: `EmbeddingsNNBPM`, `GlobalPSNM`, `LocalPSNM`, `PESM`, `TopKJoinPM`).
- Ships `results/PER.csv`: 2,630 runs over D1–D10, ABTBUY, CDDB, CORA and synthetic deduplication sets of 10K–300K records.

### Runs (D2 = Abt–Buy, top-1 configurations, 10 budgets, 1 iteration)

| Workflow | Reproduced AUC / recall | Shipped AUC / recall | Notes |
|---|---|---|---|
| Join (`TopKJoinPM`, BFS, k = 5, char 5-gram TF-IDF) | 0.770 / 0.943 | 0.770 / 0.944 | matches |
| Sorted neighbourhood (`GlobalPSNM`, window 10) | 0.498 / 0.653 | 0.528 / 0.681 | close |
| PESM (CN-CBS) | 0.314 / 0.495 | 0.590 / 0.775 | does not reproduce |
| NN + BFS (`EmbeddingsNNBPM`, gtr-t5-large, k = 5) | stopped | — | about 6 s per record to embed on 4 CPU cores, about 3.5 h for D2 |

- **Unpinned dependency.** `requirements.txt` lists `pyjedai` without a version, and PESM no longer reproduces with pyJedAI 0.3.6.
- **NN workflow cost.** The NN workflow's cost is dominated by the language model. It is not usable on CPU at stream rates without a much smaller encoder.

### What the shipped results say about our problem
Trace linking inside one stream is deduplication, not linkage between two clean sources. On the shipped synthetic deduplication runs, mean progressive AUC (top-1 configurations) was:

| Workflow | 10K | 50K | 100K | 200K | 300K |
|---|---|---|---|---|---|
| Sorted neighbourhood | 0.41 | 0.40 | 0.40 | 0.41 | 0.43 |
| Sparkly | 0.43 | 0.43 | 0.43 | 0.43 | — |
| NN + BFS | 0.34 | 0.33 | 0.32 | 0.32 | 0.31 |
| PESM | 0.29 | 0.27 | 0.28 | 0.28 | 0.28 |
| Join | 0.36 | no result | no result | no result | no result |

This matches the paper's own conclusion: for deduplication, the sorting-based workflow wins on accuracy, run time and memory, and Join does not scale past about 50K records. Some failed runs are recorded as zero rather than missing (DeepBlocker reports AUC 0 on ABTBUY and CDDB), so the CSV needs filtering before averaging.

### Verdict
Use the runner and configs as the stage-4 benchmark harness, with pyJedAI pinned once a version that reproduces the shipped PESM numbers is found (0.3.6 does not). Start our scheduling with sorted neighbourhood, the measured winner for deduplication at scale, and treat NN + BFS as a challenger rather than the default.

## Effect on the plan
- **DynaHash:** the authors' code, with the five defects fixed and regression-tested, is the LSH candidate source. It lives in `third_party/dynahash`; any compiled port is validated against it.
- **PER:** the runner and configs over pinned pyJedAI form the scheduling benchmark. Sorted neighbourhood is the primary method; NN + BFS and Join are challengers.
- **Licensing:** no longer a factor. Research-code reliability (wrong formulas, unpinned dependencies, non-reproducing configs) is listed as a risk instead.

## Reproduce

```bash
python3.12 -m venv venv && . venv/bin/activate
pip install mmh3 numpy pandas rocksdb-py pyjedai==0.3.6
cd DynaHash && python main_ACM_DBLP.py && python main_Scholar_DBLP.py && python main_probe.py
cd ../PER-Design-Space-Exploration
# point the dataset paths in a copy of grid_config/{sn,pesm,join}_experiments_top_1.json at ./datasets, set iterations to 1
MPLBACKEND=Agg python run_workflow_setup.py --config_path <copy>.json --store_folder_path ./out/ --dataset d2
```
