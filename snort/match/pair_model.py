"""Calibrated logistic pair model with isotonic calibration (plan 4.4, v1).

Logistic-regression coefficients are the explanation (raw-margin
contributions); decisions use the calibrated probability.
"""

from __future__ import annotations

import hashlib
import json

import numpy as np
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedShuffleSplit

from snort.match.features import FEATURE_NAMES


class CalibratedPairModel:
    """Logistic regression + isotonic calibration on held-out pairs."""

    def __init__(self, C: float = 1.0, seed: int = 0) -> None:
        self.C = C
        self.seed = seed
        self.clf = LogisticRegression(C=C, random_state=seed, max_iter=5000)
        self.calibrator = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
        self._fitted = False

    @property
    def fitted(self) -> bool:
        return self._fitted

    def fit(self, X: list[list[float]], y: list[int]) -> "CalibratedPairModel":
        Xa = np.asarray(X, dtype=float)
        ya = np.asarray(y, dtype=int)
        if Xa.ndim != 2 or Xa.shape[1] != len(FEATURE_NAMES):
            raise ValueError(f"expected {len(FEATURE_NAMES)} features per row")
        if len(set(ya.tolist())) < 2:
            raise ValueError("need both positive and negative pairs to fit")
        n = len(ya)
        if n >= 12 and min(np.bincount(ya)) >= 2:
            splitter = StratifiedShuffleSplit(
                n_splits=1, test_size=0.25, random_state=self.seed
            )
            train_idx, cal_idx = next(splitter.split(Xa, ya))
            self.clf.fit(Xa[train_idx], ya[train_idx])
            raw_cal = self._raw_margin(Xa[cal_idx])
            self.calibrator.fit(raw_cal, ya[cal_idx])
        else:
            # Too few pairs for a held-out split: fit and calibrate in-sample.
            self.clf.fit(Xa, ya)
            self.calibrator.fit(self._raw_margin(Xa), ya)
        self._fitted = True
        return self

    def _raw_margin(self, Xa: np.ndarray) -> np.ndarray:
        return Xa @ self.clf.coef_[0] + self.clf.intercept_[0]

    def raw_margin(self, X: list[list[float]]) -> np.ndarray:
        self._check()
        return self._raw_margin(np.asarray(X, dtype=float))

    def predict_proba(self, X: list[list[float]]) -> np.ndarray:
        """Calibrated P(match) for each pair, clipped to [0, 1]."""
        self._check()
        margins = self._raw_margin(np.asarray(X, dtype=float))
        probs = self.calibrator.predict(margins)
        return np.clip(np.asarray(probs, dtype=float), 0.0, 1.0)

    def contributions(self, x: list[float]) -> dict[str, float]:
        """Per-feature raw-margin contributions (coef * value)."""
        self._check()
        xa = np.asarray(x, dtype=float)
        return {
            name: float(c * v)
            for name, c, v in zip(FEATURE_NAMES, self.clf.coef_[0], xa)
        }

    def decision_context(self) -> dict[str, str]:
        """Hashes identifying the model + params for the decision ledger."""
        self._check()
        payload = json.dumps(
            {
                "model": "logistic+isotonic",
                "C": self.C,
                "seed": self.seed,
                "features": list(FEATURE_NAMES),
                "coef": [float(c) for c in self.clf.coef_[0]],
                "intercept": float(self.clf.intercept_[0]),
            },
            sort_keys=True,
        ).encode("utf-8")
        return {"model_hash": hashlib.blake2b(payload, digest_size=16).hexdigest()}

    def calibration_error(
        self, X: list[list[float]], y: list[int], n_bins: int = 10
    ) -> float:
        """Expected calibration error of the calibrated probabilities."""
        probs = self.predict_proba(X)
        ya = np.asarray(y, dtype=float)
        edges = np.linspace(0.0, 1.0, n_bins + 1)
        ece = 0.0
        for lo, hi in zip(edges[:-1], edges[1:]):
            mask = (probs > lo) & (probs <= hi) if lo > 0 else (probs <= hi)
            if mask.sum() == 0:
                continue
            ece += mask.mean() * abs(probs[mask].mean() - ya[mask].mean())
        return float(ece)

    def _check(self) -> None:
        if not self._fitted:
            raise RuntimeError("model is not fitted")
