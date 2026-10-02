"""Candidate retrieval: LSH over MinHash, indicator postings, provenance joins."""

from snort.retrieve.v1_index import MAX_CANDIDATES, RetrievalIndex, lsh_num_tables

__all__ = ["MAX_CANDIDATES", "RetrievalIndex", "lsh_num_tables"]
