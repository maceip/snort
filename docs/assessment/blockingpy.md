# Assessment: BlockingPy (ncn-foreigners/BlockingPy)

The repository was cloned, its test suite run, its own benchmark reproduced, and its deduplication mode run on attacker command sessions from the Unveiling-CTAs corpus. This note records what works, what does not, and what it changes in `docs/plan.md`.

Environment: 4-core cloud container, Python 3.12. `ncn-foreigners/BlockingPy@b7185f0` (0.2.8) installed from the repo with the faiss, hnswlib, voyager, annoy, pynndescent and mlpack backends.

## What it is

- `Blocker.block()` turns records into character n-gram document-term matrices or embeddings, then runs one approximate nearest-neighbour backend (faiss, hnswlib, voyager, annoy, pynndescent, mlpack, or faiss on GPU).
- It builds a graph from the neighbour pairs and returns its weakly connected components (igraph) as blocks.
- `eval()` reports pairs completeness (recall), reduction ratio and a confusion matrix against true blocks.
- **Batch only.** Every `block()` call builds a fresh index; there is no incremental insert.

## Runs

| Run | Result |
|---|---|
| Test suite | 179 passed, 22 skipped (GPU and optional backends), 1 xfailed, 1 xpassed; 3 min 7 s |
| Bundled benchmark, 15,000 records, faiss LSH | recall 0.9044 (shipped 0.8997), reduction ratio 0.99970, 2.9 s |
| Bundled benchmark, 15,000 records, faiss HNSW | recall 0.9134 (shipped 0.9130), 5.4 s |
| Bundled benchmark, 150,000 records, faiss LSH | recall 0.8182 (shipped 0.8183), 80 s |
| Deduplication of 9,988 CTA command sessions (94 actors), faiss HNSW | see below |

**Its own benchmark reproduces.** Recall falls as the data grows: the shipped HNSW results go from 0.96 at 1,500 records to 0.83 at 150,000.

**On attacker command sessions:**
- In deduplication mode each record is linked only to its single nearest neighbour; `k_search` only widens the search. Results were identical for `k_search` = 2, 5 and 10.
- 85.9% of those nearest-neighbour links join two sessions of the same actor.
- After the connected-components step, only 66.5% of the pairs inside a block belong to the same actor.
- The largest block holds 1,031 sessions from 7 different actors, and 44% of all sessions sit in blocks that mix actors.
- Same-actor pair recall within blocks is 5.6%: each actor is spread over many small blocks while a few large blocks merge actors.

## Verdict

- **Reliable as an offline tool.** It is a well-tested library whose numbers reproduce.
- **Not on the live path:** it rebuilds the index on every call and cannot insert incrementally.
- **Its block output is the wrong unit for security data.** The connected-components step turns 86%-pure neighbour links into 67%-pure blocks on real attacker sessions, because shared tooling chains different actors together.
- **Where it fits:** offline comparison of ANN backends and parameters, using its `eval()` metrics.

Its connected components are never used as groups. The plan already says this; it is now backed by measurement.

## Reproduce

```bash
python3.12 -m venv bp && bp/bin/pip install -e BlockingPy/packages/blockingpy-core[faiss] -e BlockingPy/packages/blockingpy pytest
cd BlockingPy && ../bp/bin/python -m pytest -q tests
# benchmark: Blocker().block(x=df["txt"], ann="faiss", control_ann={"faiss": {"k_search": 5, "index_type": "lsh", "lsh_nbits": 1}})
# CTA chaining: one record per session (joined SCLC command text), same call, then group sessions by returned block
```
