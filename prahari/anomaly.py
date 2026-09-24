"""Isolation Forest — unsupervised anomaly detection, in pure Python.

The trained detectors answer "is this one of the threats we know?". This answers
the harder question a real SOC lives with: "is this NOT normal, even though it
matches no signature?" — the zero-day / unknown-behaviour case.

Isolation Forest (Liu, Ting & Zhou, ICDM 2008) is the standard unsupervised
method for it, and it fits our constraints exactly: it trains only on *benign*
traffic (no attack labels needed), scores in one pass, and is explainable — an
anomaly is a point the forest isolates in very few random splits. We implement
it from first principles so it stays inside the zero-dependency guarantee: no
scikit-learn, no numpy, just the standard library.

Score is in [0, 1]; ~0.5 is the expected value for a normal point and values
approaching 1 mark a point the forest isolates almost immediately — an outlier.
"""
from __future__ import annotations

import json
import math
import random
from pathlib import Path

MODEL_DIR = Path(__file__).resolve().parent / "models"
_EULER = 0.5772156649015329


def _c(n: int) -> float:
    """Expected path length of an unsuccessful BST search over n points — the
    normalisation that makes scores comparable across sample sizes."""
    if n <= 1:
        return 1.0
    return 2.0 * (math.log(n - 1) + _EULER) - 2.0 * (n - 1) / n


class _Node:
    __slots__ = ("f", "q", "left", "right", "size")

    def __init__(self, f=None, q=None, left=None, right=None, size=0):
        self.f, self.q, self.left, self.right, self.size = f, q, left, right, size


class IsolationForest:
    def __init__(self, n_trees: int = 100, sample_size: int = 256, seed: int = 7):
        self.n_trees = n_trees
        self.sample_size = sample_size
        self.seed = seed
        self.trees: list[_Node] = []
        self.height_limit = 0
        self.dim = 0

    # -- fit ------------------------------------------------------------------
    def _build(self, pts: list[list[float]], depth: int, rng: random.Random) -> _Node:
        n = len(pts)
        if depth >= self.height_limit or n <= 1:
            return _Node(size=n)
        # pick a feature that actually varies, else make a leaf
        feats = list(range(self.dim))
        rng.shuffle(feats)
        for f in feats:
            lo = min(p[f] for p in pts)
            hi = max(p[f] for p in pts)
            if hi > lo:
                q = rng.uniform(lo, hi)
                left = [p for p in pts if p[f] < q]
                right = [p for p in pts if p[f] >= q]
                return _Node(f=f, q=q,
                             left=self._build(left, depth + 1, rng),
                             right=self._build(right, depth + 1, rng), size=n)
        return _Node(size=n)

    def fit(self, X: list[list[float]]) -> "IsolationForest":
        if not X:
            return self
        self.dim = len(X[0])
        m = min(self.sample_size, len(X))
        self.height_limit = math.ceil(math.log2(max(m, 2)))
        rng = random.Random(self.seed)
        self.trees = []
        for _ in range(self.n_trees):
            sample = rng.sample(X, m) if len(X) > m else list(X)
            self.trees.append(self._build(sample, 0, rng))
        return self

    # -- score ----------------------------------------------------------------
    @staticmethod
    def _path(x: list[float], node: _Node, depth: int) -> float:
        while node.f is not None:
            node = node.left if x[node.f] < node.q else node.right
            depth += 1
        return depth + _c(node.size)

    def score(self, x: list[float]) -> float:
        if not self.trees:
            return 0.0
        avg = sum(self._path(x, t, 0) for t in self.trees) / len(self.trees)
        return 2.0 ** (-avg / _c(self.sample_size))

    # -- persistence ----------------------------------------------------------
    def _pack(self, node: _Node):
        if node.f is None:
            return {"s": node.size}
        return {"f": node.f, "q": node.q, "l": self._pack(node.left),
                "r": self._pack(node.right), "n": node.size}

    def _unpack(self, d) -> _Node:
        if "f" not in d:
            return _Node(size=d["s"])
        return _Node(f=d["f"], q=d["q"], left=self._unpack(d["l"]),
                     right=self._unpack(d["r"]), size=d["n"])

    def to_dict(self) -> dict:
        return {"n_trees": self.n_trees, "sample_size": self.sample_size,
                "height_limit": self.height_limit, "dim": self.dim,
                "trees": [self._pack(t) for t in self.trees]}

    def save(self, name: str) -> Path:
        MODEL_DIR.mkdir(parents=True, exist_ok=True)
        p = MODEL_DIR / f"{name}.json"
        p.write_text(json.dumps(self.to_dict()), encoding="utf-8")
        return p

    @classmethod
    def from_dict(cls, d: dict) -> "IsolationForest":
        m = cls(d["n_trees"], d["sample_size"])
        m.height_limit, m.dim = d["height_limit"], d["dim"]
        m.trees = [m._unpack(t) for t in d["trees"]]
        return m

    @classmethod
    def load(cls, name: str) -> "IsolationForest | None":
        p = MODEL_DIR / f"{name}.json"
        if not p.exists():
            return None
        return cls.from_dict(json.loads(p.read_text(encoding="utf-8")))
