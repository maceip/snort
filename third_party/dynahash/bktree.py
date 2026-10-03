"""BK-tree for DynaHash multi-probe lookup.

Vendored from https://github.com/dimkar121/DynaHash @ 14fbaa9 (BKTree.py),
Adapted with streaming `insert` and iterative traversal so deep bucket trees
do not exceed Python's recursion limit (fix 4 in ../README.md).
"""

import gc


class BKTree:
    def distance(self, v1, v2):
        s1 = v1.split("_")
        s2 = v2.split("_")
        return sum([1 for i, j in zip(s1, s2) if i != j])

    def __init__(self, items, usegc=False):
        self.nodes = {}
        try:
            self.root = next(items)
        except StopIteration:
            self.root = ""
            return

        self.nodes[self.root] = []  # the value is a list of tuples (word, distance)
        gc_on = gc.isenabled()
        if not usegc:
            gc.disable()
        for el in items:
            if el not in self.nodes:  # do not add duplicates
                self._addLeaf(self.root, el)
        if gc_on:
            gc.enable()

    def insert(self, item):
        """Insert one bucket key; no-op if already present. Returns True if added."""
        if item in self.nodes:
            return False
        if not self.nodes:
            # Empty tree (built from no keys): the item becomes the root.
            self.root = item
            self.nodes[item] = []
            return True
        self._addLeaf(self.root, item)
        return True

    def _addLeaf(self, root, item):
        while True:
            dist = self.distance(root, item)
            if dist == 0:
                return
            for arc in self.nodes[root]:
                if dist == arc[1]:
                    root = arc[0]
                    break
            else:
                if item not in self.nodes:
                    self.nodes[item] = []
                self.nodes[root].append((item, dist))
                return

    def find(self, item, threshold):
        "Return an array with all the items found with distance <= threshold from item."
        result = []
        if self.nodes:
            self._finder(self.root, item, threshold, result)
        return result

    def _finder(self, root, item, threshold, result):
        result.extend(self._xfinder(root, item, threshold))

    def xfind(self, item, threshold):
        "Like find, but yields items lazily. This is slower than find if you need a list."
        if self.nodes:
            return self._xfinder(self.root, item, threshold)

    def _xfinder(self, root, item, threshold):
        pending = [root]
        while pending:
            node = pending.pop()
            dist = self.distance(node, item)
            if dist <= threshold:
                yield node
            dmin = dist - threshold
            dmax = dist + threshold
            pending.extend(
                arc[0] for arc in reversed(self.nodes[node]) if dmin <= arc[1] <= dmax
            )
