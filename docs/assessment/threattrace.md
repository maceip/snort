# Assessment: ThreatTrace (janusza/ThreatTrace-Cyber-Attack-Detection)

The repository was cloned and both R notebooks were run end to end on the shipped FedCSIS 2023 data, with the minimum patches needed to make them run (listed below). Its compaction step was then checked against a token-exact implementation of the same rules, and two suspected defects were measured. This note records what works, what does not, and what it changes in `docs/plan.md`.

Environment: 4-core cloud container, 15 GB RAM, R 4.6.1 (CRAN), data.table 1.18.6, text2vec, xgboost, glmnet, e1071. `janusza/ThreatTrace-Cyber-Attack-Detection@7611014`.

## What it is

- **Data:** FedCSIS 2023 Challenge audit logs from an IoT device.
  - The records are 60-second windows labelled attack or not.
  - The shipped RData holds the process-discovery, training and test splits: 9.5M, 18.8M and 10.1M events.
- **Trace:** the events of one PID within one window. The training side has 478,066 traces.
- **Activity:** `uid_syscall_success`, giving 76 distinct activities.
- **Notebook 1, process mining and embeddings:**
  1. Collapse runs of the same activity into `m_<activity>`.
  2. Mine frequent length-2 sequences, with support ≥ 1% of traces or of positions.
  3. Replace each frequent pair with a `seq_k` token, then collapse runs of those.
  4. Train 32-d GloVe on the compacted traces.
     - Label tokens are left in the training traces, so the embeddings are "supervised".
- **Notebook 2, detection models:**
  - Per trace: `[count, mean, mean of squares, min, max]` of its token vectors.
  - Per window:
    - those trace vectors aggregated into `[mean, std, min, max]`;
    - length metadata;
    - 25 fuzzy c-means memberships.
  - Baseline features: counts, most common uid and syscall, success rate.
  - Models: XGBoost (2,000 trees, depth 10) and LASSO logistic regression. The metric is ROC AUC on the competition's time-forward test split.
- **Published (Table 1, 32-d):**

  | Model | Basic features | ThreatTrace |
  |---|---|---|
  | GLMnet | 0.540 | 0.746 |
  | XGBoost | 0.891 | 0.940 |

## Patches needed to run it

| ID | Problem | Patch |
|---|---|---|
| P1 | Notebook 1 lists raw audit-log folders and attack lists that are not shipped | Removed; they feed only exploratory statistics |
| P2 | (Not required.) The training table was read from the shipped CSV (`data/model_training_data_v2.7z`). The RData copy has the same 18,838,658 rows | P2_CHECK |
| — | `bupaverse` is not on CRAN; current `Matrix`/`arules` need R ≥ 4.4 | R 4.6 from CRAN; `bupaR` with its process-map packages instead; plotting chunks skipped |
| P4 | Notebook 2 loads `IoT_case_traces_compacted_v1.RData` and `..._glove_..._v2.RData`, which no shipped notebook writes (notebook 1 writes `..._supervised_embedds.RData` and `..._v3.RData`) | Mapped to notebook 1's outputs |
| P4b | Notebook 1's training traces keep the label as first and last token (`START,FALSE,…,FALSE`); notebook 1 strips them in its own embedding chunk, notebook 2 does not | Stripped the same way, so training and test traces share a format |
| P6 | XGBoost `device = "gpu"` | `"cpu"` |
| P7 | The frequent-sequence miner calls `str_extract_all` for every candidate on every trace and did not finish its first pass in 12 min on 4 cores; the pair pass has about 60× more candidates | Same counts computed on tokens; checked identical to the original on 3,000 traces (61 single and 2,000 pair candidates) before use. Mining then takes about a minute |
| P9 | Trace vectors are combined with `foreach(.combine = "rbind")`, which copies the growing matrix every 100 traces; for 640k traces this took about 65 min of a 75-min notebook | For the variant runs only: collect a list and bind once (identical matrix) |

With these, notebook 1 reproduces the paper's vocabulary: 193 distinct activities after compaction (paper: "193 activities").

## Runs

| Run | GLMnet AUC | XGBoost AUC |
|---|---|---|
| Published, basic features | 0.540 | 0.891 |
| Published, ThreatTrace 32-d | 0.746 | 0.940 |
| Reproduced, basic features | **0.540** | 0.904 |
| Reproduced, ThreatTrace 32-d (as shipped) | 0.771 | **0.915** |
| `pmax` fix to the std features | 0.748 | 0.910 |
| `pmax` fix, without fuzzy c-means features | 0.772 | 0.920 |
| Run-length collapse only, no mined pairs | GloVe diverges with the authors' settings (finding 5) | — |
| Basic features + log activity counts per window (76 unigrams, no embeddings) | 0.744 | **0.927** |
| Basic features + log activity and activity-bigram counts | 0.763 | **0.928** |

## Findings

1. **The compaction corrupts about a quarter of traces.**
   - **How it was measured:** on 20,000 sampled test traces, a Python port of the R regexes reproduced the R output exactly (20,000 of 20,000). A token-exact implementation of the same rules differed on 5,294 traces (26.5%).
   - **Cause 1:** pair patterns are not anchored to token boundaries. `root_close_yes,root_openat_yes` matches inside `m_root_close_yes,root_openat_yes` and produces `m_seq_1` ("several seq_1") from four closes and one open.
   - **Cause 2:** run patterns are not end-anchored. `(,seq_1){2,}` matches the start of `,seq_1,seq_12…`.
   - **Effect:** 12 tokens are produced only by these errors. The most frequent is `m_seq_38`, which occurs 2,407 times in the sample.
   - **Each cause matters on its own:**
     - anchoring both patterns to token boundaries removes all 5,294 differences;
     - fixing only the pair patterns leaves 2,898;
     - fixing only the run patterns leaves 3,948.
2. **The std features carry no trace information.** `normalize_trace_embeddings` uses `max(0, …)` where `pmax` was intended. `max` returns one scalar over all windows, so each of the 32 "std" columns is a function of the window's event count only. Measured: the median std column has 905 distinct values over 20,044 windows, which is the number of distinct event counts. With `pmax` it has 9,729.
3. **Fuzzy c-means forces membership.** The memberships of every window sum to 1 (checked on every row). Windows with no embeddable trace get −1 in every column. The clustering is fit on training and test windows together, which is transductive, though it uses no labels.
4. **The pipeline as shipped does not chain** (P4, P4b), and two steps do not scale: the frequent-sequence miner (P7) and the trace-vector combine (P9).
5. **The embedding settings are brittle.** With run-length collapse only (no mined pairs), traces average 55 tokens instead of 13, and the authors' GloVe configuration diverges ("cost is too big") at learning rates 0.20, 0.15, 0.05 and 0.01. A variant without pair compaction could therefore not be trained as specified. A bag-of-activities baseline was run instead.
6. **The representation does not beat plain activity counts on its own data.**
   - **The data match the paper:** the basic-feature GLMnet reproduces the published AUC to three decimals (0.540).
   - **XGBoost:**
     - The published gain over basic features is +0.049 (0.891 → 0.940). Here it is +0.011 (0.904 → 0.915).
     - With `pmax` fixed and c-means dropped, the best ThreatTrace configuration reaches 0.920.
     - Basic features plus log counts of the 76 activities reach 0.927, and 0.928 with activity bigrams.
   - **GLMnet:** ThreatTrace's features lead counts by less than 0.01 (0.772 vs 0.763).
   - **How strong this is:**
     - With about 175 attack windows in the test set, differences near 0.01 are within noise.
     - The supported conclusion is that the representation does not clearly beat counts, not that counts are better.
     - Fuzzy c-means memberships add nothing for XGBoost: 0.920 without them, 0.910 with them.

## Verdict

- **Kept:**
  - the idea of a trace-level pooled vector of token-vector statistics `[count, mean, std, min, max]`, as one feature family among several;
  - mined-pair compaction, as an optional step that must win its ablation;
  - the FedCSIS data as a sanity check, since its baseline reproduces exactly.
- **Not used:**
  - the R implementation (regex compaction, `max` instead of `pmax`, steps that do not scale);
  - fuzzy c-means;
  - GloVe trained with label tokens in the corpus.
- **Plan status:**
  - **Stage 2 baseline:** bag-of-activities counts, unigrams and bigrams. The pooled vector stays only if it beats counts on the plan's own measure, same-campaign recall@10.
  - **Scope:** ThreatTrace measures window-level detection, not retrieval, so its results bound the representation's value for detection only.

## Reproduce

```bash
# R 4.6 from CRAN; install data.table arules arulesSequences text2vec uwot bupaR fasttime caTools xgboost glmnet e1071 mltools doFuture
7z x data/model_training_data_v2.7z
knitr::purl the two notebooks, apply P1–P9 (see this note), run notebook 1 then notebook 2
python compaction_check.py   # R regex compaction vs token-exact, on notebook 2's exported test-trace sample
```
