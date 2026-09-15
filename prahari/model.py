"""A small logistic-regression implementation and score calibration.

Two of the seven detectors (beaconing, DGA) use a fitted model rather than a
hand-set threshold. Keeping the implementation in-repo and dependency-free means
the training procedure is inspectable, which is what constraint (e) of the
problem statement asks for when it demands documentation of the training and
validation approach.
"""
from __future__ import annotations

import json
import math
import random
from pathlib import Path

MODEL_DIR = Path(__file__).resolve().parent / "models"


def sigmoid(z: float) -> float:
    if z >= 0:
        return 1.0 / (1.0 + math.exp(-z))
    e = math.exp(z)
    return e / (1.0 + e)


class LogisticRegression:
    """Batch gradient descent with L2. Small, honest, and enough for tabular
    features on a few thousand samples."""

    def __init__(self, feature_names: list[str], lr: float = 0.5,
                 epochs: int = 600, l2: float = 1e-3, balanced: bool = True):
        self.feature_names = feature_names
        self.w = {f: 0.0 for f in feature_names}
        self.b = 0.0
        self.lr, self.epochs, self.l2 = lr, epochs, l2
        # Network traffic is wildly imbalanced. Without re-weighting, gradient
        # descent simply learns to answer "benign" and reports 99.6% accuracy.
        # The weight is capped: an uncapped ratio of several hundred to one just
        # flips the failure mode and makes the model answer "malicious".
        self.balanced = balanced
        self.max_pos_weight = 25.0
        self.threshold = 0.5
        self.mu: dict[str, float] = {}
        self.sigma: dict[str, float] = {}

    # -- standardisation keeps gradient descent well-behaved ------------------
    def _fit_scaler(self, X: list[dict[str, float]]) -> None:
        n = len(X)
        for f in self.feature_names:
            vals = [x.get(f, 0.0) for x in X]
            m = sum(vals) / n
            var = sum((v - m) ** 2 for v in vals) / max(n - 1, 1)
            self.mu[f] = m
            self.sigma[f] = math.sqrt(var) or 1.0

    def _z(self, x: dict[str, float]) -> float:
        return self.b + sum(
            self.w[f] * ((x.get(f, 0.0) - self.mu[f]) / self.sigma[f])
            for f in self.feature_names
        )

    def fit(self, X: list[dict[str, float]], y: list[int]) -> "LogisticRegression":
        self._fit_scaler(X)
        n = len(X)
        pos, neg = sum(y), len(y) - sum(y)
        w_pos = min(neg / pos, self.max_pos_weight) if (self.balanced and pos) else 1.0
        for _ in range(self.epochs):
            gw = {f: 0.0 for f in self.feature_names}
            gb = 0.0
            wsum = 0.0
            for xi, yi in zip(X, y):
                cw = w_pos if yi else 1.0
                err = (sigmoid(self._z(xi)) - yi) * cw
                gb += err
                wsum += cw
                for f in self.feature_names:
                    gw[f] += err * ((xi.get(f, 0.0) - self.mu[f]) / self.sigma[f])
            wsum = wsum or n
            self.b -= self.lr * gb / wsum
            for f in self.feature_names:
                self.w[f] -= self.lr * (gw[f] / wsum + self.l2 * self.w[f])
        return self

    def predict_proba(self, x: dict[str, float]) -> float:
        if not self.mu:
            return 0.0
        return sigmoid(self._z(x))

    # -- persistence ----------------------------------------------------------
    def choose_threshold(self, X, y, betas=(1.0,)) -> float:
        """Pick the operating point on the TRAINING data, then leave it alone.

        Reporting held-out numbers at a threshold tuned on the held-out set is a
        subtle way of cheating; choosing it here keeps the evaluation honest.
        """
        best_t, best_f1 = 0.5, -1.0
        scored = [(self.predict_proba(x), yi) for x, yi in zip(X, y)]
        for i in range(5, 100, 2):
            t = i / 100.0
            tp = sum(1 for s_, yi in scored if s_ >= t and yi)
            fp = sum(1 for s_, yi in scored if s_ >= t and not yi)
            fn = sum(1 for s_, yi in scored if s_ < t and yi)
            if tp == 0:
                continue
            prec, rec = tp / (tp + fp), tp / (tp + fn)
            f1 = 2 * prec * rec / (prec + rec)
            if f1 > best_f1:
                best_f1, best_t = f1, t
        self.threshold = best_t
        return best_t

    def to_dict(self) -> dict:
        return {"features": self.feature_names, "w": self.w, "b": self.b,
                "mu": self.mu, "sigma": self.sigma, "threshold": self.threshold}

    @classmethod
    def from_dict(cls, d: dict) -> "LogisticRegression":
        m = cls(d["features"])
        m.w, m.b, m.mu, m.sigma = d["w"], d["b"], d["mu"], d["sigma"]
        m.threshold = d.get("threshold", 0.5)
        return m

    def save(self, name: str) -> Path:
        MODEL_DIR.mkdir(parents=True, exist_ok=True)
        p = MODEL_DIR / f"{name}.json"
        p.write_text(json.dumps(self.to_dict(), indent=2))
        return p

    @classmethod
    def load(cls, name: str) -> "LogisticRegression | None":
        p = MODEL_DIR / f"{name}.json"
        if not p.exists():
            return None
        return cls.from_dict(json.loads(p.read_text()))


def train_test_split_temporal(rows: list[tuple], frac: float = 0.7):
    """Split on time, never at random.

    Flows from a single attack burst are highly correlated; a random split puts
    them on both sides, the model memorises the burst, and the reported accuracy
    is meaningless. Every published NIDS number that looks too good usually
    traces back to this one mistake.
    """
    rows = sorted(rows, key=lambda r: r[0])
    cut = int(len(rows) * frac)
    return rows[:cut], rows[cut:]


def isotonic_like_calibration(scores: list[float], labels: list[int], bins: int = 10):
    """Map raw model scores to observed empirical precision, so a reported
    confidence of 0.9 actually means roughly nine in ten.

    Returns a lookup that the detectors apply before an alert is emitted.
    """
    if not scores:
        return {"edges": [], "values": []}
    pairs = sorted(zip(scores, labels))
    size = max(1, len(pairs) // bins)
    edges, values = [], []
    for i in range(0, len(pairs), size):
        chunk = pairs[i:i + size]
        if not chunk:
            continue
        edges.append(chunk[0][0])
        values.append(sum(c[1] for c in chunk) / len(chunk))
    # enforce monotonicity (pool adjacent violators, simplified)
    for i in range(1, len(values)):
        if values[i] < values[i - 1]:
            values[i] = values[i - 1]
    return {"edges": edges, "values": values}


def apply_calibration(cal: dict, score: float) -> float:
    edges, values = cal.get("edges", []), cal.get("values", [])
    if not edges:
        return score
    out = values[0]
    for e, v in zip(edges, values):
        if score >= e:
            out = v
    return out
