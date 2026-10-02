"""DynaHash vendored for snort, with the five stage-3 fixes.

Upstream: https://github.com/dimkar121/DynaHash, pinned at 14fbaa9.
Pristine upstream copies live in ./original/ and are exercised only by the
differential regression tests in ./tests/.

The five fixes (docs/assessment/dynahash-per.md, docs/plan.md section 4.3):

1. Table count from theta. Upstream sets p = 1 - th, which agrees with the
   paper's L = ceil(ln delta / ln(1 - p^k)) only at th = 0.5. Here p = th,
   so L = 147 at the default and e.g. L = 49 (not 562) at th = 0.6.
2. Record identity separate from blocking content. Upstream keys every store
   by the blocked string itself, so two records with equal content collapse
   into one. Here every method takes ``record_id`` plus ``tokens``; equal
   token sets under distinct ids are stored and retrieved independently.
3. Bounded memory. The vector store ``vs`` evicts the longest-stored record
   once ``max_records`` is exceeded (stale bucket entries are skipped
   lazily at query time), and each bucket list is capped at ``max_bucket``
   entries with FIFO eviction. Defaults: 1M records, 500 per bucket (w).
4. Streaming multi-probe. Bucket keys created by later ``add`` calls are
   inserted into the BK-trees immediately, so ``probe_get`` sees them
   without a ``finalize`` rebuild. ``finalize`` still rebuilds from the
   current keys and stays idempotent.
5. Token-set input. MinHash is computed over a caller-supplied iterable of
   token strings (e.g. trace shingles) instead of hardcoded character
   2-grams. ``eps`` now sizes ``m`` (identical 116 at the default 0.1) and
   ``q`` remains the default width of the ``*_text`` convenience helpers,
   which bridge raw strings via character q-grams.

In-memory bucket key format ("_"-joined component hashes) is unchanged, so
vectors built from character 2-gram token sets are bit-identical to
upstream's for the same strings and seed; the tests assert this.
"""

import json
import math
import os
import pickle
import random
import time

import mmh3
import numpy as np

from bktree import BKTree


class DynaHash:

    def __init__(self, k=6, th=0.5, eps=0.1, delta=0.1, q=2, omega=0, db=False,
                 db_dir="", max_records=1000000, max_bucket=500, seed=None):
        if not 0 < th < 1:
            raise ValueError("th must be in (0, 1), got %r" % (th,))
        if not 0 < eps < 1:
            raise ValueError("eps must be in (0, 1), got %r" % (eps,))
        if not 0 < delta < 1:
            raise ValueError("delta must be in (0, 1), got %r" % (delta,))
        if k < 1:
            raise ValueError("k must be >= 1, got %r" % (k,))
        if not 0 <= omega <= k:
            raise ValueError("omega must satisfy 0 <= omega <= k, got %r" % (omega,))
        if max_records < 1:
            raise ValueError("max_records must be >= 1, got %r" % (max_records,))
        if max_bucket < 1:
            raise ValueError("max_bucket must be >= 1, got %r" % (max_bucket,))
        self.delta = delta
        self.eps = eps
        self.th = th
        self.k = k

        # Fix 5: m honours eps (unchanged 116 at the default eps = 0.1).
        self.m = math.ceil(math.log(1 / eps) / (2 * eps ** 2))
        self.t = math.ceil((1 - self.th) * self.m)
        # Fix 1: p = th per the paper, not 1 - th.
        p = self.th
        self.L = math.ceil(math.log(self.delta) / math.log(1 - p ** self.k))
        self.omega = omega
        s_omega = 0
        for i in range(omega + 1):
            s_omega += p ** (self.k - i)
        self.newL = math.ceil(math.log(self.delta) / math.log(1 - s_omega))
        if self.omega > 0:
            print("L_omega=", self.newL, " hash tables used instead of L=", self.L, "m=", self.m)
        else:
            print("L=", self.L, "m=", self.m)

        self.q = q
        self.max_records = max_records
        self.max_bucket = max_bucket
        self._rng = random.Random(seed)
        self.db = False
        if db is True:
            self.db = True
            self.db_dir = db_dir
            rocksdbpy = self._rocksdb()
            opts = rocksdbpy.Option()
            opts.create_if_missing(True)
            opts.set_max_open_files(1000)
            self.db1 = rocksdbpy.open(db_dir, opts)
            self.db2 = rocksdbpy.open(db_dir + '/objects/', opts)
        self.createSamples()
        self.dictB = [dict() for l in range(self.L)]
        self.vs = {}
        # Fix 4: trees exist from construction so streaming adds stay visible.
        self.trees = [BKTree(iter([])) for l in range(self.L)]

    @staticmethod
    def _rocksdb():
        try:
            import rocksdbpy
        except ModuleNotFoundError:
            raise RuntimeError(
                "DynaHash persistent mode needs the 'rocksdb-py' package "
                "(PyPI name rocksdb-py, module rocksdbpy): pip install rocksdb-py")
        return rocksdbpy

    def Hamming(self, v1, v2):
        return sum([1 for i, j in zip(v1, v2) if i != j])

    def createSamples(self):
        self.samples = []
        if self.db is True:
            if os.path.exists(self.db_dir + '/objects/samples.pickle'):
                with open(self.db_dir + '/objects/samples.pickle', 'rb') as handle:
                    self.samples = pickle.load(handle)
                    return
        lm = list(range(self.m))
        for l in range(self.L):
            s = self._rng.sample(lm, self.k)
            self.samples.append(s)
        if self.db is True:
            with open(self.db_dir + '/objects/samples.pickle', 'wb') as handle:
                pickle.dump(self.samples, handle, protocol=pickle.HIGHEST_PROTOCOL)

    def str_to_MinHash(self, str1, q, seed=0):
        """Kept for compatibility and differential testing; prefer token input."""
        return min([mmh3.hash(str1[i:i + q], seed) for i in range(len(str1) - q + 1)])

    @staticmethod
    def char_qgrams(text, q):
        """Split a raw string into character q-grams (the upstream input as tokens)."""
        return [text[i:i + q] for i in range(len(text) - q + 1)]

    def _minhash(self, tokens):
        """MinHash signature over a token set. Fix 5: no hardcoded 2-grams."""
        if isinstance(tokens, (str, bytes, bytearray)):
            raise TypeError(
                "tokens must be an iterable of token strings, not a single "
                "string; use add_text/get_text/probe_get_text or "
                "char_qgrams() for raw strings")
        toks = list(tokens)
        if not toks:
            raise ValueError("cannot MinHash an empty token set")
        return [min(mmh3.hash(t, seed) for t in toks) for seed in range(self.m)]

    @staticmethod
    def _bucket_key(sample, sig):
        keys = ""
        for s in sample:
            keys += str(sig[s]) + "_"
        return keys[:-1]

    def finalize(self):
        # Fix 4: rebuild from current keys; idempotent, keeps batch use working.
        self.trees = [BKTree(iter(self.dictB[l].keys())) for l in range(self.L)]

    def vectorize(self, tokens):
        return self._minhash(tokens)

    def vectorize_text(self, text, q=None):
        return self._minhash(self.char_qgrams(text, self.q if q is None else q))

    def add(self, record_id, tokens, value=None):
        """Index one record. Fix 2: id is independent of the blocked tokens."""
        sig = self._minhash(tokens)
        if record_id in self.vs:
            self.vs[record_id] = {"v": value, "h": sig}
        else:
            # Fix 3: bound the vector store; stale bucket entries are
            # skipped lazily at query time via the vs lookup below.
            if len(self.vs) >= self.max_records:
                oldest = next(iter(self.vs))
                del self.vs[oldest]
            self.vs[record_id] = {"v": value, "h": sig}
        for l in range(self.L):
            key = self._bucket_key(self.samples[l], sig)
            bucket = self.dictB[l]
            if key in bucket:
                lst = bucket[key]
                if record_id not in lst:
                    if len(lst) >= self.max_bucket:
                        lst.pop(0)
                    lst.append(record_id)
            else:
                bucket[key] = [record_id]
                # Fix 4: streaming adds stay visible to multi-probe.
                self.trees[l].insert(key)

    def add_text(self, record_id, text, value=None, q=None):
        """String convenience over add(); distinct ids never collapse."""
        return self.add(record_id, self.char_qgrams(text, self.q if q is None else q), value)

    def get(self, tokens):
        r = self._minhash(tokens)
        matchingKeys = {}
        results = []
        no_items = 0
        st = time.time()
        for l in range(self.L):
            key = self._bucket_key(self.samples[l], r)
            if key in self.dictB[l]:
                key_list = self.dictB[l][key]
                for k in key_list:
                    if k in matchingKeys.keys():
                        continue
                    entry = self.vs.get(k)
                    if entry is None:
                        continue  # evicted under the max_records bound
                    no_items += 1
                    if self.Hamming(r, entry["h"]) <= self.t:
                        matchingKeys[k] = 1
                        results.append({"k": k, "v": entry["v"]})
        end = time.time()
        queryTime = round(end - st, 4)
        return results, no_items, queryTime

    def get_text(self, text, q=None):
        return self.get(self.char_qgrams(text, self.q if q is None else q))

    def get_ranks(self, tokens, th):
        r = self._minhash(tokens)
        matchingKeys = {}
        no_items = 0
        st = time.time()
        th0 = 0.95
        bins = []
        for th00 in np.arange(0.95, th - 0.05, -0.05):
            t = math.ceil((1 - th00) * self.m)
            bins.append(t)
        ranks = [[] for _ in range(len(bins))]

        t = math.ceil((1 - th0) * self.m)
        L1 = 0
        while True:
            p = th0
            L2 = math.ceil(math.log(self.delta) / math.log(1 - p ** self.k))
            # The index holds self.L tables; shallower ranks need no more.
            L2 = min(L2, len(self.samples))
            for l in range(L1, L2):
                sample = self.samples[l]
                key = self._bucket_key(sample, r)
                if key in self.dictB[l]:
                    key_list = self.dictB[l][key]
                    for k in key_list:
                        if k in matchingKeys.keys():
                            continue
                        entry = self.vs.get(k)
                        if entry is None:
                            continue  # evicted under the max_records bound
                        no_items += 1
                        dist = self.Hamming(r, entry["h"])
                        if dist <= self.t:
                            matchingKeys[k] = 1
                            bin = np.digitize([dist], bins)
                            if bin[0] < len(ranks):
                                ranks[bin[0]].append({"k": k, "v": entry["v"]})
            L1 = L2
            th0 = th0 - 0.05
            t = math.ceil((1 - th0) * self.m)
            if round(th0, 2) < round(th, 2):
                break

        end = time.time()
        query_time = round(end - st, 4)
        return ranks, no_items, query_time

    def probe_get(self, tokens):
        r = self._minhash(tokens)
        matchingKeys = {}
        results = []
        no_items = 0
        st = time.time()
        scanned_blocks = 0
        sum_blocks = 0
        avg_blocks = 0

        for l in range(self.newL):
            sample = self.samples[l]
            keys = self._bucket_key(sample, r)

            kks = [keys]
            extra_keys = self.trees[l].find(keys, self.omega)
            for kk1 in extra_keys:
                if kk1 != keys:
                    kks.append(kk1)

            scanned_blocks += len(kks)
            sum_blocks += len(kks) + 1
            for keys in kks:
                if keys in self.dictB[l]:
                    key_list = self.dictB[l][keys]
                    for k in key_list:
                        if k in matchingKeys.keys():
                            continue
                        entry = self.vs.get(k)
                        if entry is None:
                            continue  # evicted under the max_records bound
                        no_items += 1
                        if self.Hamming(r, entry["h"]) <= self.t:
                            matchingKeys[k] = 1
                            results.append({"k": k, "v": entry["v"]})

            if scanned_blocks >= self.newL:
                avg_blocks = sum_blocks / (l + 1)
                break

        end = time.time()
        queryTime = round(end - st, 4)
        return results, no_items, queryTime, avg_blocks

    def probe_get_text(self, text, q=None):
        return self.probe_get(self.char_qgrams(text, self.q if q is None else q))

    def get_items_no(self):
        return len(self.vs.keys())

    def get_ground_truth(self, tokens):
        ground_truth = []
        r = self._minhash(tokens)
        for k in self.vs.keys():
            arr = self.vs[k]["h"]
            dist = self.Hamming(r, arr)
            if dist <= self.t:
                ground_truth.append(k)
        return ground_truth

    def get_db_ground_truth(self, tokens):
        self._rocksdb()
        ground_truth = []
        m_key = self._minhash(tokens)
        for k, v in self.db2.iterator():
            dict_obj = bytes.decode(v, 'utf-8')
            dict_obj = json.loads(dict_obj)
            dist = self.Hamming(m_key, dict_obj["h"])
            if dist <= self.t:
                k1 = bytes.decode(k, 'utf-8')
                ground_truth.append(k1)
        return ground_truth

    def db_get(self, tokens):
        self._rocksdb()
        results = []
        m_key = self._minhash(tokens)
        no_items = 0
        matchingKeys = {}
        st = time.time()
        for l in range(self.L):
            sample = self.samples[l]
            keys = "".join([str(m_key[s]) for s in sample])
            ks = "".join([str(l), ":", keys])
            bkey = bytes(ks, "utf-8")
            for k, v in self.db1.iterator(mode="from", key=bkey):
                k1 = bytes.decode(k, 'utf-8')
                if not k1.startswith(ks):
                    break
                v1 = bytes.decode(v, 'utf-8')
                if v1 in matchingKeys.keys():
                    continue
                entry = self.db2.get(v)
                if entry is None:
                    continue
                no_items += 1
                dict_obj = bytes.decode(entry, 'utf-8')
                dict_obj = json.loads(dict_obj)
                dist = self.Hamming(m_key, dict_obj["h"])
                if dist <= self.t:
                    matchingKeys[v1] = 1
                    results.append({"k": v1, "v": dict_obj["v"]})
        end = time.time()
        queryTime = round(end - st, 4)
        return results, no_items, queryTime

    def db_add(self, record_id, tokens, value=None):
        """Persistent add. Fix 2 applies here too: id separate from tokens."""
        if not isinstance(record_id, str):
            raise TypeError("db record_id must be str, got %s" % type(record_id).__name__)
        rocksdbpy = self._rocksdb()
        r = self._minhash(tokens)
        bKey = bytes(record_id, 'utf-8')
        b_dict = json.dumps({"v": value, "h": r}, indent=2).encode('utf-8')
        self.db2.set(bKey, b_dict)

        for l in range(self.L):
            sample = self.samples[l]
            keys = "".join([str(r[s]) for s in sample])
            ts = time.time()
            k = "".join([str(l), ":", keys, "!", str(ts)])
            k = bytes(k, 'utf-8')
            self.db1.set(k, bKey)
