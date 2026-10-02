# Assessment: Unveiling-CTAs (bogertaNET/Unveiling-CTAs)

This note covers:
- **Reproduction:** the repository was cloned and read, and its shipped trained models were evaluated on the authors' exact test split.
- **Baseline:** a TF-IDF baseline was run on the same data and split.
- **Time-forward test:** the corpus was rebuilt with session timestamps so that the models could be scored on a split ordered by time.

It records what works, what does not, and what it changes in `docs/plan.md`.

Environment: 4-core cloud container, CPU only, Python 3.12, torch 2 (CPU), scikit-learn 1.7. `bogertaNET/Unveiling-CTAs@9727280`.

## What it is

- **Data:** `data/x/data_with_sclc.json`.
  - Commands that threat actors ran through Cobalt Strike beacons, keyed by actor and session (beacon).
  - Each command has its text, type, beacon ID, timestamp and an ATT&CK tactic.
  - 94 non-empty actors, 9,988 sessions, 134,948 commands, November 2019 to December 2022.
  - Command text is normalized by the SCLC converter (`data_prep/sclc.py`).
- **Unit of analysis:** one session.
  - Its commands are joined, tokenized and cleaned; sessions over 256 tokens are dropped.
  - The result is shipped as token-ID sequences in `data_timestamped_all.parquet`, without session IDs or timestamps.
- **Labels:** actor names.
  - Actors whose names contain `plki` or `joke` are merged into one class `sf`, sampled to 1,500 sessions.
  - A class `other` is dropped as wrongly labelled.
- **Tasks:** classify a session's actor among the 4, 10 or 34 actors with more than 1,000, 50 or 10 sessions.
- **Split:** random and stratified, 70/15/15 with `random_state=42` (`data_prep/create_datasets.py`).
- **Models:** a transformer-plus-CNN hybrid (`experiments/tune_hybridarchitecture.py`) and fine-tuned BERT, RoBERTa, SecureBERT and DarkBERT. Trained hybrid weights ship in `models/`.

## Runs

| Run | 4 actors | 10 actors | 34 actors |
|---|---|---|---|
| Test-set size (authors' split code) | 781 | 868 | 959 |
| Published hybrid accuracy (`results.json`) | 0.9513 | 0.9378 | 0.8926 |
| Shipped `hybrid_{4,10,34}.pt` on that test set | **0.9513** | **0.9378** | **0.8926** |
| Best published BERT-family accuracy | 0.921 | 0.923 | 0.870 |
| TF-IDF (word 1–2-grams) + logistic regression, trained on train only | 0.962 | 0.940 | 0.910 |
| TF-IDF + logistic regression, trained on train + validation (as the final hybrids were) | **0.962** | **0.948** | **0.926** |
| Test sessions that also appear verbatim in training | 9.2% | 8.8% | 8.8% |

Time-forward check on the rebuilt corpus:
- **Rebuilt corpus:** 7,935 sessions with session IDs and first-command timestamps, built with the authors' own preprocessing steps.
- **Same classes and actor lists:** the published 4/10/34-actor label lists, with the same `sf` merge.
- **Test sets:**
  - random split: the authors' 70/15/15 procedure;
  - time-forward split: the latest 15% of each actor's sessions.

| Model | Split | 4 actors | 10 actors | 34 actors |
|---|---|---|---|---|
| TF-IDF + LR | random | 0.956 | 0.947 | 0.923 |
| TF-IDF + LR | random, verbatim duplicates removed from test | 0.952 | 0.942 | 0.916 |
| TF-IDF + LR | time-forward | **0.797** | **0.661** | **0.653** |
| Authors' hybrid, retrained (their hyperparameters, 30 epochs) | random | 0.950 | — | — |
| Authors' hybrid, retrained (their hyperparameters, 30 epochs) | time-forward | **0.747** | — | — |

## Findings

1. **The published numbers reproduce exactly** from the shipped weights.
2. **A TF-IDF baseline matches or beats every published model, on both splits.** On the authors' own data and split, logistic regression over word 1–2-grams scores above the hybrid and all four BERT-family models at every label count. It trains in seconds on a CPU. The paper reports no such baseline.
3. **The random split overstates accuracy.**
   - **The evaluation itself:** with a random split, sessions from the same period of an actor's activity land in both train and test.
   - **Under a time-forward split:** TF-IDF accuracy falls by 16 points (4 actors) and 27–29 points (10 and 34 actors).
   - **The hybrid falls too:** retrained on the rebuilt corpus with the authors' hyperparameters, it matches its published score on the random split (0.950 vs 0.951) and falls to 0.747 time-forward, below TF-IDF's 0.797.
   - **Not caused by duplicates:** verbatim duplicate sessions explain less than one point of this, so the gap comes from actors changing their commands over time.
   - Attribution in practice is time-forward: new activity is matched against older activity.
4. **Correction to an earlier claim in this plan.** The earlier plan said the split leaks through overlapping 32-command windows from one beacon. That is wrong: the pipeline builds one row per session, and no windows are cut. The real issues are the random split (finding 3) and about 9% verbatim duplicates.
5. **The corpus is the valuable part.** It has 94 actors with real beacon sessions, timestamps and ATT&CK tactics, and it is the only public data set in this plan with actor labels on command activity.
6. **Engineering:**
   - The training scripts depend on DataLoader pickles and support files that are not shipped, so they need `data_prep` to be run first.
   - The shipped parquet drops session IDs and timestamps, so grouped or time-forward splits need the JSON rebuilt, as done here.

## Verdict

- **Kept:**
  - the corpus and its SCLC normalizer;
  - the actor labels and the `sf` merge, documented as a choice the authors made.
- **Not used:**
  - the hybrid and BERT models, which do not beat TF-IDF;
  - the published scores, which come from a random split.
- **Plan status:**
  - **Starting classifier:** TF-IDF + logistic regression is the plan's starting execution-content classifier; the hybrid becomes a challenger.
  - **Evaluation:** every CTA result in this project is reported on the time-forward split, with the random-split figure shown only for comparison with the paper.
  - **Calibration:** the attribution thresholds in §4.6 are calibrated on time-forward data. Time-forward accuracy of 0.65–0.80 means most CTA sessions will end as *candidates* or *unresolved*, not *attributed*. That is the intended behaviour.

## Reproduce

```bash
# exact split and shipped models (uses data/x/data_timestamped_all.parquet and models/hybrid_*.pt)
python shipped_eval.py
# rebuild sessions with timestamps from data_with_sclc.json using data_prep's TimeStamper, TweetTokenizer and preprocess, purge > 256 tokens
python build.py && python tfidf_eval.py && python hybrid_eval.py 1000 30
```
