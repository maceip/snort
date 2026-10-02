"""Regression tests for the five vendored DynaHash fixes.

Each fix is tested against the pristine upstream copy in ../original/
(dimkar121/DynaHash @ 14fbaa9) on the bundled names data
(fixtures/names_small.csv, a copy of upstream's data/names_small.csv).

Run from the repository root with either runner:

    python -m unittest discover -s third_party/dynahash/tests -t third_party/dynahash
    python -m pytest third_party/dynahash/tests/

Needs mmh3 and numpy (see third_party/requirements.txt). RocksDB tests use
an in-memory rocksdbpy stub, so rocksdb-py is never required here.
"""

import csv
import importlib.util
import math
import os
import random
import sys
import tempfile
import unittest

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
PKG_DIR = os.path.dirname(TESTS_DIR)
ORIG_DIR = os.path.join(PKG_DIR, "original")
FIXTURE = os.path.join(TESTS_DIR, "fixtures", "names_small.csv")
sys.path.insert(0, PKG_DIR)

from dynahash import DynaHash  # noqa: E402

SEED = 20240517


def load_original():
    """Load pristine upstream DynaHash + BKTree without touching repo imports."""
    saved = sys.modules.pop("BKTree", None)
    try:
        spec = importlib.util.spec_from_file_location(
            "BKTree", os.path.join(ORIG_DIR, "BKTree.py"))
        bk = importlib.util.module_from_spec(spec)
        sys.modules["BKTree"] = bk
        spec.loader.exec_module(bk)
        spec2 = importlib.util.spec_from_file_location(
            "OriginalDynaHash", os.path.join(ORIG_DIR, "DynaHash.py"))
        mod = importlib.util.module_from_spec(spec2)
        sys.modules["OriginalDynaHash"] = mod
        spec2.loader.exec_module(mod)
        return mod.DynaHash
    finally:
        sys.modules.pop("BKTree", None)
        sys.modules.pop("OriginalDynaHash", None)
        if saved is not None:
            sys.modules["BKTree"] = saved


OriginalDynaHash = load_original()


def load_names(limit=None):
    with open(FIXTURE, newline="", encoding="utf8") as fh:
        rows = list(csv.reader(fh, delimiter=";"))
    rows = [(r[0], r[1]) for r in rows[1:] if r]
    return rows[:limit] if limit is not None else rows


def qgrams(text, q=2):
    return [text[i:i + q] for i in range(len(text) - q + 1)]


def make_pair(seed=SEED, **kwargs):
    """Seeded (fixed, original) pair with identical hash-table samples."""
    random.seed(seed)
    orig = OriginalDynaHash(**{k: v for k, v in kwargs.items()
                               if k in ("k", "th", "eps", "delta", "q", "omega")})
    fixed = DynaHash(seed=seed, **kwargs)
    return fixed, orig


class FakeRocksDB:
    """Minimal in-memory stand-in for the rocksdbpy open/iterator/get/set API."""

    def __init__(self):
        self._data = {}

    def set(self, k, v):
        self._data[bytes(k)] = bytes(v)

    def get(self, k):
        return self._data.get(bytes(k))

    def iterator(self, mode=None, key=None):
        keys = sorted(self._data)
        if mode == "from" and key is not None:
            keys = [k for k in keys if k >= bytes(key)]
        return iter([(k, self._data[k]) for k in keys])


class FakeRocksModule:
    """Module-shaped fake: open() returns one FakeRocksDB per path."""

    def __init__(self):
        self._dbs = {}

    def Option(self):
        class Opt:
            def create_if_missing(self, v):
                pass

            def set_max_open_files(self, v):
                pass
        return Opt()

    def open(self, path, opts):
        return self._dbs.setdefault(path, FakeRocksDB())


class TestTableCount(unittest.TestCase):
    """Fix 1: L follows the paper's formula in th, not 1 - th."""

    def paper_L(self, th, delta=0.1, k=6):
        return math.ceil(math.log(delta) / math.log(1 - th ** k))

    def test_paper_values(self):
        # Values from docs/assessment/dynahash-per.md section 1.
        for th, expected in [(0.5, 147), (0.6, 49), (0.7, 19), (0.8, 8)]:
            with self.subTest(th=th):
                self.assertEqual(DynaHash(th=th).L, expected)
                self.assertEqual(DynaHash(th=th).L, self.paper_L(th))

    def test_paper_abt_buy_case(self):
        # The paper's Abt-Buy run (th=0.45, delta=0.001) needs 829 tables;
        # upstream builds 246.
        self.assertEqual(DynaHash(th=0.45, delta=0.001).L, 829)

    def test_default_matches_original(self):
        fixed, orig = make_pair()
        self.assertEqual(fixed.L, 147)
        self.assertEqual(orig.L, 147)
        self.assertEqual(fixed.m, orig.m)
        self.assertEqual(fixed.samples, orig.samples)

    def test_multiprobe_table_count(self):
        fixed, _ = make_pair(omega=1)
        self.assertEqual(fixed.newL, 48)

    def test_invalid_params_rejected(self):
        for kwargs in ({"th": 0.0}, {"th": 1.5}, {"eps": 0.0}, {"delta": -0.1},
                       {"k": 0}, {"omega": 7}, {"max_records": 0}, {"max_bucket": 0}):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    DynaHash(**kwargs)


class TestTokenInput(unittest.TestCase):
    """Fix 5: MinHash over caller token sets; eps sizes m."""

    def test_default_m_matches_original(self):
        fixed, orig = make_pair()
        self.assertEqual(fixed.m, 116)
        self.assertEqual(orig.m, 116)

    def test_eps_sizes_m(self):
        for eps in (0.2, 0.05):
            with self.subTest(eps=eps):
                expected = math.ceil(math.log(1 / eps) / (2 * eps ** 2))
                self.assertEqual(DynaHash(eps=eps).m, expected)

    def test_token_minhash_matches_char_bigrams(self):
        # Token sets built from character 2-grams reproduce upstream vectors.
        fixed, orig = make_pair()
        for name, _ in load_names(10):
            with self.subTest(name=name):
                expected = [orig.str_to_MinHash(name, 2, j) for j in range(orig.m)]
                self.assertEqual(fixed.vectorize(qgrams(name)), expected)
                self.assertEqual(fixed.vectorize_text(name), expected)

    def test_raw_strings_rejected(self):
        dh = DynaHash()
        with self.assertRaises(TypeError):
            dh.add("id1", "some raw string", None)
        with self.assertRaises(TypeError):
            dh.get("some raw string")
        with self.assertRaises(TypeError):
            dh.vectorize("some raw string")

    def test_empty_token_set_rejected(self):
        dh = DynaHash()
        with self.assertRaises(ValueError):
            dh.add("id1", [], None)

    def test_retrieval_parity_with_original(self):
        # Same samples + same vectors => same buckets and same results.
        # Duplicate names are skipped here (upstream collapses them by key;
        # that bug has its own test below).
        fixed, orig = make_pair()
        names = []
        seen = set()
        for name, year in load_names(500):
            if name not in seen:
                seen.add(name)
                names.append((name, year))
            if len(names) == 200:
                break
        ids = {}
        for i, (name, year) in enumerate(names):
            rid = "r%d" % i
            ids[name] = rid
            orig.add(name, year)
            fixed.add(rid, qgrams(name), year)
        self.assertEqual(fixed.samples, orig.samples)
        self.assertEqual(fixed.get_items_no(), orig.get_items_no())
        for name, _ in names[:20]:
            with self.subTest(query=name):
                f_res, f_n, _ = fixed.get(qgrams(name))
                o_res, o_n, _ = orig.get(name)
                self.assertEqual(f_n, o_n)
                self.assertEqual({r["k"] for r in f_res},
                                 {ids[r["k"]] for r in o_res})

    def test_get_ranks_parity_with_original(self):
        fixed, orig = make_pair()
        names = []
        seen = set()
        for name, year in load_names(200):
            if name not in seen:
                seen.add(name)
                names.append((name, year))
            if len(names) == 50:
                break
        ids = {}
        for i, (name, year) in enumerate(names):
            ids[name] = "r%d" % i
            orig.add(name, year)
            fixed.add(ids[name], qgrams(name), year)
        for name, _ in names[:5]:
            with self.subTest(query=name):
                f_ranks, f_n, _ = fixed.get_ranks(qgrams(name), 0.5)
                o_ranks, o_n, _ = orig.get_ranks(name, 0.5)
                self.assertEqual(f_n, o_n)
                self.assertEqual(len(f_ranks), len(o_ranks))
                for f_rank, o_rank in zip(f_ranks, o_ranks):
                    self.assertEqual({r["k"] for r in f_rank},
                                     {ids[r["k"]] for r in o_rank})


class TestSeparateIdentity(unittest.TestCase):
    """Fix 2: equal content under distinct ids stays distinct."""

    def test_duplicate_content_keeps_distinct_ids(self):
        dh = DynaHash(seed=SEED)
        toks = qgrams("AnHai Doan")
        dh.add("trace-a", toks, "v1")
        dh.add("trace-b", toks, "v2")
        self.assertEqual(dh.get_items_no(), 2)
        res, _, _ = dh.get(toks)
        self.assertEqual({r["k"] for r in res}, {"trace-a", "trace-b"})
        self.assertEqual({r["v"] for r in res}, {"v1", "v2"})

    def test_original_collapses_same_key(self):
        # Documents the upstream bug fix 2 removes.
        _, orig = make_pair()
        orig.add("AnHai Doan", "v1")
        orig.add("AnHai Doan", "v2")
        self.assertEqual(orig.get_items_no(), 1)

    def test_readd_same_id_updates_value(self):
        dh = DynaHash(seed=SEED)
        dh.add("trace-a", qgrams("AnHai Doan"), "v1")
        dh.add("trace-a", qgrams("AnHai Doan"), "v2")
        self.assertEqual(dh.get_items_no(), 1)
        res, _, _ = dh.get(qgrams("AnHai Doan"))
        self.assertEqual([(r["k"], r["v"]) for r in res], [("trace-a", "v2")])


class TestBoundedMemory(unittest.TestCase):
    """Fix 3: bounded vector store and bounded bucket lists."""

    def test_vector_store_evicts_oldest(self):
        dh = DynaHash(seed=SEED, max_records=100)
        for i in range(150):
            dh.add("r%d" % i, ["tok%d" % i], i)
        self.assertEqual(dh.get_items_no(), 100)
        self.assertNotIn("r0", dh.vs)
        self.assertNotIn("r49", dh.vs)
        self.assertIn("r50", dh.vs)
        self.assertIn("r149", dh.vs)

    def test_queries_skip_evicted_without_error(self):
        dh = DynaHash(seed=SEED, max_records=100)
        for i in range(150):
            dh.add("r%d" % i, ["tok%d" % i], i)
        res, _, _ = dh.get(["tok0"])
        self.assertTrue(all(r["k"] != "r0" for r in res))
        res, _, _ = dh.get(["tok149"])
        self.assertIn("r149", {r["k"] for r in res})

    def test_bucket_lists_capped(self):
        dh = DynaHash(seed=SEED, max_bucket=8)
        toks = qgrams("AnHai Doan")
        for i in range(20):
            dh.add("r%d" % i, toks, i)
        self.assertEqual(dh.get_items_no(), 20)
        for bucket in dh.dictB:
            for lst in bucket.values():
                self.assertLessEqual(len(lst), 8)
        res, _, _ = dh.get(toks)
        self.assertEqual(len(res), 8)


class TestStreamingProbe(unittest.TestCase):
    """Fix 4: multi-probe trees see bucket keys added after finalize."""

    def test_late_adds_visible_without_refinalize(self):
        names = []
        seen = set()
        for name, _ in load_names(500):
            if name not in seen:
                seen.add(name)
                names.append(name)
            if len(names) == 100:
                break
        early, late = names[:50], names[50:]
        fixed, orig = make_pair(omega=1)
        for name in early:
            orig.add(name, "")
            fixed.add(name, qgrams(name), "")
        orig.finalize()
        fixed.finalize()
        for name in late:
            orig.add(name, "")
            fixed.add(name, qgrams(name), "")
        # Structural check: every late bucket key reached the fixed trees,
        # while the original trees still hold early keys only (its defect).
        for l in range(fixed.newL):
            for name in late:
                key = fixed._bucket_key(fixed.samples[l], fixed.vs[name]["h"])
                self.assertIn(key, fixed.trees[l].nodes)
            expected = set()
            for name in early:
                sig = [orig.str_to_MinHash(name, 2, j) for j in range(orig.m)]
                expected.add("_".join(str(sig[s]) for s in orig.samples[l]))
            self.assertEqual(set(orig.trees[l].nodes.keys()), expected)
        # End to end: fixed multi-probe finds everything the original finds
        # (its trees are a superset), plus near matches the original misses.
        strict = 0
        for name in names:
            f_res = {r["k"] for r in fixed.probe_get(qgrams(name))[0]}
            o_res = {r["k"] for r in orig.probe_get(name)[0]}
            self.assertLessEqual(o_res, f_res)
            if f_res > o_res:
                strict += 1
        self.assertGreaterEqual(strict, 1)

    def test_finalize_idempotent(self):
        dh = DynaHash(seed=SEED, omega=1)
        for name, _ in load_names(20):
            dh.add_text(name, name, "")
        dh.finalize()
        before = [sorted(t.nodes.keys()) for t in dh.trees]
        dh.finalize()
        after = [sorted(t.nodes.keys()) for t in dh.trees]
        self.assertEqual(before, after)


class TestPackaging(unittest.TestCase):
    """Fix 6 (packaging): correct PyPI names; no hard RocksDB import."""

    def test_no_hard_rocksdb_dependency(self):
        self.assertNotIn("rocksdbpy", sys.modules)
        dh = DynaHash(seed=SEED)
        dh.add("r1", ["tok"], "v")
        with self.assertRaises(RuntimeError) as ctx:
            dh.db_add("r1", ["tok"], "v")
        self.assertIn("rocksdb-py", str(ctx.exception))

    def test_pinned_third_party_requirements(self):
        req = os.path.join(PKG_DIR, "..", "requirements.txt")
        with open(req, encoding="utf8") as fh:
            content = fh.read()
        # rottnest LogCloud pin plus its transitive getdaft pin.
        self.assertIn("rottnest==1.5.0", content)
        self.assertIn("getdaft==0.3.15", content)
        # Correct PyPI name for the RocksDB binding (upstream wrote
        # `rocksdbpy`, which does not exist on PyPI).
        self.assertIn("rocksdb-py", content)


class TestRocksDBMode(unittest.TestCase):
    """Persistent store keeps fix 2 (separate ids) via a stubbed binding."""

    def setUp(self):
        self._saved = sys.modules.get("rocksdbpy")
        self.fake = FakeRocksModule()
        sys.modules["rocksdbpy"] = self.fake
        self._tmp = tempfile.TemporaryDirectory()
        os.makedirs(os.path.join(self._tmp.name, "objects"), exist_ok=True)

    def tearDown(self):
        if self._saved is not None:
            sys.modules["rocksdbpy"] = self._saved
        else:
            sys.modules.pop("rocksdbpy", None)
        self._tmp.cleanup()

    def test_db_roundtrip_keeps_distinct_ids(self):
        dh = DynaHash(seed=SEED, db=True, db_dir=self._tmp.name)
        toks = qgrams("AnHai Doan")
        dh.db_add("trace-a", toks, "v1")
        dh.db_add("trace-b", toks, "v2")
        res, _, _ = dh.db_get(toks)
        self.assertEqual({r["k"] for r in res}, {"trace-a", "trace-b"})
        self.assertEqual(set(dh.get_db_ground_truth(toks)), {"trace-a", "trace-b"})


if __name__ == "__main__":
    unittest.main()
