  <img width="151" height="200" alt="ztled" src="https://github.com/user-attachments/assets/65b8e012-8162-42ec-a5a4-965403957840" />

single-process telemetry store and trace grouping engine with lance, duckdb, and blake3 tamper proofing.

## capabilities

- live ingestion: append incoming json or cta events directly to an append-only wal.
- columnar storage: seal wal segments into immutable lance datasets with blake3 hash tracking.
- fast search: query sealed lance files and the unsealed wal tail in a single pass using duckdb.
- hybrid text retrieval: rank hits with lance bm25 full-text indexing and boolean sql filters.
- trace grouping: group related events and score pairs without multi-process overhead.
- tamper verification: verify that stored files and decision ledgers have not been altered.
- cross-platform: prebuilt binaries for linux, macos, windows, and android.

## Query Architecture

```mermaid
---
config:
  theme: base
  flowchart:
    curve: basis
    nodeSpacing: 30
    rankSpacing: 38
  themeVariables:
    primaryColor: "#161B22"
    primaryTextColor: "#E6EDF3"
    primaryBorderColor: "#6E7681"
    lineColor: "#8B949E"
    secondaryColor: "#21262D"
    tertiaryColor: "#0D1117"
---
flowchart TB

    SRC["Telemetry / Dataset Sources"]
    Q["Incoming Queries"]

    SRC --> READ["Readers"]
    READ --> WAL["BLAKE3 WAL"]
    WAL --> BUF["In-Memory Buffer"]

    Q --> TEXT["Free-text / Keywords"]
    Q --> SQL["Structured / Analytics"]

    TEXT --> SDK["Lance Native SDK"]
    SQL --> DUCK["DuckDB"]

    BUF -->|"seal / append"| LANCE["Lance Dataset"]

    SDK --> LANCE
    DUCK --> BUF
    DUCK --> LANCE

    LANCE --> INDEX["Native Indexes
    BTREE · Full-Text · Vector"]

    classDef source fill:#21262D,stroke:#6E7681,color:#E6EDF3,stroke-width:1px
    classDef engine fill:#161B22,stroke:#8B949E,color:#E6EDF3,stroke-width:1.5px
    classDef storage fill:#0D1117,stroke:#C9D1D9,color:#FFFFFF,stroke-width:2px
    classDef index fill:#161B22,stroke:#6E7681,color:#C9D1D9,stroke-width:1px

    class SRC,Q source
    class SDK,DUCK engine
    class LANCE storage
    class INDEX index
```
## install


download prebuilt binaries from github releases or install locally:

```bash
git clone https://github.com/maceip/snort.git
cd snort
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt -e .
```

## usage

### 1. run the end-to-end demo

```bash
snort demo --out bench/results/demo
```

### 2. ingest raw events

```bash
snort ingest --format jsonl --wal-dir wal events.jsonl
```

### 3. seal to lance

```bash
snort seal --wal-dir wal --sealed-dir sealed
```

### 4. build indexes

```bash
snort index --sealed-dir sealed --index-dir index
```

### 5. search evidence

fast scan over sealed segments and wal tail:

```bash
snort search "powershell" --sealed-dir sealed --wal-dir wal
```

hybrid bm25 full-text search with structured filter:

```bash
snort search "powershell" --sealed-dir sealed --bm25 --filter "host = 'ws-2'"
```

### 6. verify store integrity

```bash
snort verify --wal-dir wal --sealed-dir sealed
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
