# Vendored DynaHash (stage-3 LSH)

Upstream: `dimkar121/DynaHash`, pinned at `14fbaa9`
(assessment: `docs/assessment/dynahash-per.md`).
Pristine upstream copies of `DynaHash.py` and `BKTree.py` at that commit live
in `original/` and are used only by the differential regression tests.

## What changed vs upstream (`dynahash.py`, `bktree.py`)

1. **Table count from θ** — `p = th`, so `L = ceil(ln δ / ln(1 − θ^k))`
   (147 at the default; 49 at θ = 0.6; 829 for the paper's θ = 0.45,
   δ = 0.001 run). Upstream's `p = 1 − th` agrees only at θ = 0.5.
2. **Record id separate from blocking content** — `add(record_id, tokens,
   value)` / `get(tokens)` / `probe_get(tokens)` / `get_ranks(tokens, th)`
   plus `db_add`/`db_get`. Equal token sets under distinct ids are stored
   and retrieved independently; re-adding an id updates its value/vector.
3. **Bounded memory** — `vs` evicts the longest-stored record past
   `max_records` (default 1M; bucket entries for evicted ids are skipped
   lazily at query time); each bucket list is capped at `max_bucket`
   (default 500, FIFO). Paper settings live at construction:
   θ = 0.5, δ = 0.1, k = 6, φ = 4 (via `get_ranks`), w = 500, ω = 1.
4. **Streaming multi-probe** — `add` inserts new bucket keys into the
   BK-trees (`bktree.BKTree.insert`), so `probe_get` sees post-`finalize`
   records. `finalize()` rebuilds from current keys and is idempotent.
5. **Token-set input** — MinHash over caller token strings (trace shingles
   in stage 3). `eps` now sizes `m` (still 116 at the default 0.1); `q`
   remains the default width of the `*_text` helpers, which bridge raw
   strings through character q-grams. Raw `str` input raises `TypeError`.
6. **Packaging** — `mmh3`/`numpy` pinned in `third_party/requirements.txt`;
   the RocksDB binding is imported lazily under its real PyPI name
   (`rocksdb-py`, module `rocksdbpy`) with a helpful error when absent.

In-memory bucket key format is unchanged, so token sets built from
character 2-grams give bit-identical vectors to upstream for the same
strings and seed.

## Tests

`tests/test_dynahash_fixes.py` (stdlib `unittest`, needs `mmh3` + `numpy`;
bundled-data fixture in `tests/fixtures/names_small.csv`, copied from
upstream `data/names_small.csv`). From the repo root:

```bash
python -m unittest discover -s third_party/dynahash/tests -t third_party/dynahash
```

One test per fix, each checked against the pristine copy where applicable,
plus packaging and RocksDB-mode (in-memory stub) coverage.
