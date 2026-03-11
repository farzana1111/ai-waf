"""ML-based threat detector.

The :class:`ThreatDetector` wraps the trained scikit-learn pipeline and
provides a clean, typed interface for inference.  It auto-trains a fresh model
when no saved model is found on disk.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

import numpy as np
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import LabelEncoder

from waf.features import RequestFeatures
from waf.model.trainer import load_model, train_and_save

logger = logging.getLogger("ai_waf.detector")


@dataclass
class DetectionResult:
    """Output of the ML detector for a single request."""

    is_threat: bool
    label: str           # e.g. "sql_injection" or "normal"
    confidence: float    # probability assigned to the predicted label [0, 1]
    all_scores: dict[str, float]  # label → probability for all classes


class ThreatDetector:
    """ML-based WAF threat detector.

    Parameters
    ----------
    model_path:
        Path to a ``.joblib`` bundle (created by
        :func:`~waf.model.trainer.train_and_save`).  If the file does not exist
        the detector auto-trains a model from the built-in seed data and saves
        it to *model_path*.
    confidence_threshold:
        Minimum predicted probability to flag a request as a threat.
    """

    def __init__(
        self,
        model_path: Path | str = Path("waf/model/threat_model.joblib"),
        confidence_threshold: float = 0.70,
    ) -> None:
        self.model_path = Path(model_path)
        self.confidence_threshold = confidence_threshold
        self._pipeline: Pipeline | None = None
        self._label_encoder: LabelEncoder | None = None

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def load(self) -> None:
        """Load (or train) the model.  Safe to call multiple times."""
        if self._pipeline is not None:
            return  # already loaded

        if self.model_path.exists():
            logger.info("Loading model from %s", self.model_path)
            self._pipeline, self._label_encoder = load_model(self.model_path)
        else:
            logger.info(
                "No model found at %s — training from built-in seed data…",
                self.model_path,
            )
            self._pipeline = train_and_save(self.model_path)
            _, self._label_encoder = load_model(self.model_path)

    @property
    def is_loaded(self) -> bool:
        return self._pipeline is not None

    # ── Inference ─────────────────────────────────────────────────────────────

    def predict(self, features: RequestFeatures) -> DetectionResult:
        """Classify *features* and return a :class:`DetectionResult`.

        :meth:`load` is called lazily on the first call.
        """
        if not self.is_loaded:
            self.load()

        assert self._pipeline is not None
        assert self._label_encoder is not None

        text = [features.combined_text]
        proba: np.ndarray = self._pipeline.predict_proba(text)[0]
        predicted_idx: int = int(np.argmax(proba))
        predicted_label: str = self._label_encoder.inverse_transform([predicted_idx])[0]
        confidence: float = float(proba[predicted_idx])

        all_scores: dict[str, float] = {
            label: round(float(p), 4)
            for label, p in zip(self._label_encoder.classes_, proba)
        }

        is_threat = predicted_label != "normal" and confidence >= self.confidence_threshold

        return DetectionResult(
            is_threat=is_threat,
            label=predicted_label,
            confidence=round(confidence, 4),
            all_scores=all_scores,
        )
