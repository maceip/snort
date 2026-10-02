"""The v1 flat index and the namespaced retrieval package must coexist.

Regression test for the worktree merge: a flat ``snort/retrieve.py`` module
shadowed the ``snort/retrieve/`` package, so
``from snort.retrieve import RetrievalIndex`` failed at collection.
The flat module now lives at ``snort.retrieve.v1_index`` and the package
re-exports its public names.
"""


def test_retrieve_package_exports_v1_index():
    from snort.retrieve import MAX_CANDIDATES, RetrievalIndex, lsh_num_tables

    assert MAX_CANDIDATES == 50
    assert callable(lsh_num_tables)
    idx = RetrievalIndex()
    assert idx.theta == 0.5


def test_retrieve_submodules_importable():
    from snort.retrieve.candidates import CandidateRetriever
    from snort.retrieve.indicators import IndicatorIndex
    from snort.retrieve.minhash_lsh import MinHashLSHIndex
    from snort.retrieve.provenance import ProvenanceGraph

    assert CandidateRetriever is not None
    assert IndicatorIndex is not None
    assert MinHashLSHIndex is not None
    assert ProvenanceGraph is not None
