"""Isolated LogCloud helper (plan section 4.1, assessment logcloud.md).

Runs in a dedicated working directory, one segment at a time, because
LogCrisp writes intermediate files (``compressed/``, ``variable_*``)
into the cwd, is not reentrant, and can crash on bad input. Keeping it
in a subprocess keeps a crash from taking down the ingest process.

Requires the ``logcloud`` extra (``rottnest==1.5.0`` pinned with
``getdaft==0.3.15``; newer getdaft removed ``daft.table`` and breaks
search).
"""

from __future__ import annotations

import json
import sys


def cmd_index(parquet_path: str, column: str, name: str) -> dict:
    from rottnest import internal as logcloud

    logcloud.index_files_logcloud([parquet_path], column, name=name)
    return {"backend": "logcloud", "name": name}


def cmd_search(name: str, query: str, limit: int) -> list:
    from rottnest import internal as logcloud

    return list(logcloud.search_index_logcloud([name], query, limit))


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(json.dumps({"error": "usage: logcloud_helper index|search ..."}))
        return 2
    try:
        if argv[1] == "index":
            _, _, parquet_path, column, name = argv
            print(json.dumps(cmd_index(parquet_path, column, name)))
        elif argv[1] == "search":
            _, _, name, query, limit = argv
            print(json.dumps(cmd_search(name, query, int(limit))))
        else:
            print(json.dumps({"error": f"unknown command {argv[1]}"}))
            return 2
    except Exception as exc:  # helper must report, never traceback into the parent
        print(json.dumps({"error": str(exc)}))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
