# snort

single-process telemetry store and live trace grouping engine with lance, duckdb, and blake3 tamper-evident lineage.

## capabilities

- live ingestion: validate, deduplicate, and durably commit events to an append-only wal and live grouping pipeline.
- columnar storage: seal wal segments into immutable lance datasets with content hash tracking.
- fast search: query sealed lance files and the unsealed wal tail in a single pass using duckdb.
- hybrid text retrieval: native lance bm25 plus consistent sql filters across sealed and live events.
- trace grouping: persist overlapping groups, evidence, analyst decisions, and trained pair models; enforce three active memberships per trace.
- sql analytics: read-only aggregation and joins over events, traces, groups, memberships, and decision records.
- tamper verification: verify that stored files and decision ledgers have not been altered.
- cross-platform: prebuilt binaries for linux, macos, windows, and android.

## architecture

See the [ingest, query, and grouping diagrams](docs/architecture.md) for the
current data flow and recovery boundaries. The [live api guide](docs/live-api.md)
documents retry identities, group review, model training, and sql analytics.

## install

download prebuilt binaries from github releases or install locally:

```bash
git clone https://github.com/maceip/snort.git
cd snort
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt -e .
```

## live service

```bash
snort serve --data-dir ./snort_data --port 8080
snort ingest events.jsonl --server http://127.0.0.1:8080 --source-id sensor-1
snort query 'SELECT host, count(*) AS n FROM events GROUP BY host' --data-dir ./snort_data
```

The dashboard at `http://127.0.0.1:8080` exposes search, groups, sql, and api errors.
The default pair scorer is an identified evidence baseline; supplied pair labels
can train and persist the logistic/isotonic model through `/api/model/train`.

## usage

### 1. run the end-to-end demo

```bash
snort demo --out bench/results/demo
```

### 2. ingest raw events

Use this standalone command with the server stopped; use `--server` for a running service.

```bash
snort ingest --format jsonl --data-dir ./snort_data events.jsonl
```

### 3. seal to lance

Use the dashboard or `POST /api/seal` while the server is running.

```bash
snort seal --wal-dir ./snort_data/wal --sealed-dir ./snort_data/sealed
```

### 4. build indexes

```bash
snort index --sealed-dir ./snort_data/sealed --index-dir ./snort_data/index
```

### 5. search evidence

fast scan over sealed segments and wal tail:

```bash
snort search "powershell" --sealed-dir ./snort_data/sealed --wal-dir ./snort_data/wal
```

hybrid bm25 full-text search with structured filter:

```bash
snort search "powershell" --sealed-dir ./snort_data/sealed --wal-dir ./snort_data/wal --bm25 --filter "host = 'ws-2'"
```

### 6. verify store integrity

```bash
snort verify --wal-dir ./snort_data/wal --sealed-dir ./snort_data/sealed
snort verify-ledger bench/results/demo/ledger.jsonl
```

## releases

prebuilt standalone files published on github releases:

- `snort-macos-arm64`: macos apple silicon
- `snort-linux-x86_64`: linux 64-bit x86
- `snort-linux-arm64`: linux 64-bit arm
- `snort-windows-x64.exe`: windows 64-bit
- `snort-android-arm64`: android termux / shell binary
- `snort-android-arm64.apk`: android app package installable via adb
