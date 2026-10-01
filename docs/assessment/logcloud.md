# Assessment: LogCloud (marsupialtail/logcloud) and its Rust successor

The C++ LogCloud repository was cloned, read and run on its bundled example logs and on about 1 GB of generated logs. The Rust LogCloud inside rottnest 1.5.0 was run on the same data for comparison. This note records what works, what does not, and what it changes in `docs/plan.md`.

Environment: 4-core cloud container. `marsupialtail/logcloud@f57bec7` (installed as the PyPI wheel `rottnest==1.0.4`, Python 3.11) and `rottnest==1.5.0` (Python 3.12, `getdaft==0.3.15`). Times only indicate relative cost.

## What the repository is

- **Pipeline:** `rex` reads raw text logs. It parses a timestamp from a fixed-width prefix and writes the raw lines to Parquet (zstd, 100k-line row groups, 10 row groups per file). It trains LogCrisp templates on a 3M-line reservoir sample per batch and compresses 64 MB chunks with LogCrisp. Extracted variables are classified into 63 character-class types, and each distinct value is recorded with the row groups it occurs in.
- **Index:** `index` merges batches and writes three files per split:
  - `kauai`: values too common to index (the dictionary), templates and outlier values, with posting lists;
  - `oahu`: about 1 MB compressed blocks of distinct values per type, with posting lists;
  - `hawaii`: one FM-index per type with at least 5 oahu blocks.
- **Search:** kauai first; a dictionary hit means a full scan. Otherwise FM-index (or a brute scan of up to 5 oahu blocks), then the matching row groups are read from Parquet and filtered with a substring match.
- **LogCrisp is in this repo.** `vendored/LogCrisp_trainer_var` and `vendored/LogCrisp_compression_var` hold the LogCrisp template trainer and compressor source, plus prebuilt `Trainer.o`/`Compressor.o` that the build links. The plan previously said LogCrisp had no public code; that was wrong.
- **The Rust version reuses LogCrisp.** rottnest 1.5.0 links the same LogCrisp static libraries for training and compression and reimplements indexing and search in Rust. It indexes a string column of existing Parquet files rather than raw text files.

## Runs

| Run | Result |
|---|---|
| C++ index, 192 MB example logs (1.14M lines) | 24.8 s; index + Parquet 9.1 MB (about 21× smaller). The FM-index file is 25 bytes, because no type reaches 5 blocks at this size. |
| C++ search, 192 MB, queries inside one variable (`blk_1073746025`, `1073823744`, `46290`) | 2/2, 5/5 and 57/57 lines, matching `grep` |
| C++ index, 961 MB generated logs (HDFS logs with numeric IDs re-randomized) | 202 s (about 4.8 MB/s); Parquet 101 MB, oahu 68 MB, hawaii 166 MB |
| C++ search, 961 MB, 40 random exact block IDs | 18 found, 22 returned nothing |
| C++ search, same IDs as digits only | 18 found, 22 returned nothing; 5 queries crashed (segfault or abort) |
| Rust 1.5.0 index, same 961 MB as Parquet | 243 s; oahu 79 MB, hawaii 151 MB |
| Rust 1.5.0 search, same 40 IDs | 40 of 40, digits-only 40 of 40, about 1.3 s per query |
| Both, queries spanning a variable boundary (`10.10.34.20:72349`, `src: /10.10.34.22`, `10.10.34.22:50010`) | nothing returned, while `grep` finds 16, 22,470 and 787 lines |
| Rust 1.5.0 with the query split into its parts, searched on one part and filtered for the full string | 16 of 16 and 11 of 11, no extra lines |
| `grep` over the uncompressed 961 MB on local disk | 0.5–0.7 s per query |

The generated data uses random numeric IDs, which is close to the worst case for index size. Real telemetry should index smaller, but that has to be measured.

## Defects and limits found

1. **The C++ FM-index path misses results and crashes.** Once the FM-index is active (about 1 GB here), 22 of 40 exact-ID lookups return nothing and some numeric queries crash. Below that size the same lookups are correct. The Rust 1.5.0 implementation has neither problem on the same data.
2. **Queries spanning a variable boundary return nothing in both versions.** A query like an IP with its port, or a template fragment plus a value, cannot match a single indexed variable, and the search reports no result instead of falling back to a scan. This is exactly the kind of query used to pivot on a security indicator. Fix: split the query into variable-shaped parts, search the most selective part, and filter candidates for the full string. This was verified on the 961 MB index.
3. **The documented install no longer works.** `pip install rottnest` now installs 1.5.0, which has no `rottnest-index` command; the C++ build is `rottnest==1.0.4`, with wheels for Python 3.8–3.11 only. The 1.5.0 search breaks with current `getdaft` (`daft.table` was removed) and works with `getdaft==0.3.15`.
4. **Template IDs are local to each batch.** Templates are retrained on a sample for every batch, so the same log shape can get different IDs in different batches. They cannot serve directly as stable behaviour tokens.
5. **Batch only, with fixed working directories.** Indexing runs per batch of `index_interval` MB, and searches must scan the newest, unindexed data directly. LogCrisp writes intermediate files (`compressed/`, `variable_*`) into the current directory, so only one indexing job can run per directory. The `tail` mode in `rottnest/index.py` builds wrong paths (`dir + f` where `f` already includes `dir`) and deletes source files after indexing.
6. **Results are row groups, not lines.** Posting lists point to 100k-line row groups, and the final filter does the exact match. The C++ search also deduplicates identical lines with `.unique()`, so counts of repeated lines (for example `INFO`) come back lower than `grep`'s.
7. **On local disk at 1 GB, `grep` is faster.** LogCloud's advantage is avoiding full scans of compressed data on object storage at terabyte scale. On a workstation it has to be benchmarked at 100 GB or more against zstd + Parquet + DuckDB before it earns its place.

## Verdict

- **Index and search:** use the Rust LogCloud from rottnest 1.5.0 (pinned, with `getdaft==0.3.15`) over Parquet segments we write ourselves, so they keep our columns (timestamp, host, source sequence, event hash).
- **Reference only:** treat the C++ repository as the source for LogCrisp's trainer and compressor and as the reference for the index format. Do not use its FM-index search.
- **Required wrapper fixes before relying on it:**
  - split and verify queries that span variable boundaries;
  - scan the hot, unindexed tail directly;
  - run indexing in a dedicated working directory, one job at a time;
  - give templates content-hashed IDs.
- **Before adopting it:** benchmark against zstd + Parquet + DuckDB at 100 GB or more on the workstation.

## Reproduce

```bash
python3.11 -m venv lc && lc/bin/pip install rottnest==1.0.4 zstandard
# decompress logcloud/example-logs/*.zst into example-logs/, then:
lc/bin/rottnest-index --mode batch --dir example-logs/ --index_interval 1024 --compaction_interval 204800 \
  --index_name example --prefix_bytes 24 --prefix_format "%Y-%m-%d %T"
lc/bin/rottnest-search --index_path example --query 1073823744 --limit 1000

python3.12 -m venv rs && rs/bin/pip install rottnest==1.5.0 numpy pyarrow polars duckdb getdaft==0.3.15
# write logs to Parquet with a 'log' column, then:
rs/bin/python -c "from rottnest import internal as i; i.index_files_logcloud(['p0.parquet'], 'log', name='rs')"
rs/bin/python -c "from rottnest import internal as i; print(i.search_index_logcloud(['rs'], '72349', 1000))"
```
