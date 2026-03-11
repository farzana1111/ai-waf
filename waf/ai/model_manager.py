"""Model loading and lifecycle management."""

import logging
import pickle
from pathlib import Path

logger = logging.getLogger(__name__)


class ModelManager:
    """Load, cache, and manage ML model files from *model_dir*."""

    def __init__(self, model_dir: str = "models/"):
        self.model_dir = Path(model_dir)
        self._models: dict[str, object] = {}

    def load_model(self, model_name: str) -> object | None:
        """Load a model by *model_name* (without extension) and cache it.

        Looks for ``<model_dir>/<model_name>.pkl`` (pickle) or
        ``<model_dir>/<model_name>.joblib`` (joblib) on disk.
        Returns the loaded model object, or ``None`` on failure.
        """
        # Try joblib first, then pickle
        for ext, loader in self._loaders():
            model_path = self.model_dir / f"{model_name}{ext}"
            if model_path.is_file():
                try:
                    model = loader(str(model_path))
                    self._models[model_name] = model
                    logger.info("Loaded model '%s' from %s", model_name, model_path)
                    return model
                except Exception:
                    logger.warning("Failed to load model '%s' from %s", model_name, model_path, exc_info=True)

        logger.info("No model file found for '%s' in %s", model_name, self.model_dir)
        return None

    def get_model(self, model_name: str) -> object | None:
        """Return a previously loaded model, or attempt to load it from disk."""
        if model_name in self._models:
            return self._models[model_name]
        return self.load_model(model_name)

    def reload_models(self) -> None:
        """Re-load every model that has previously been loaded."""
        for model_name in list(self._models):
            self._models.pop(model_name, None)
            self.load_model(model_name)

    def list_models(self) -> list[str]:
        """Return the names of model files available on disk."""
        if not self.model_dir.is_dir():
            return []
        extensions = {".pkl", ".joblib"}
        return sorted(
            p.stem for p in self.model_dir.iterdir()
            if p.suffix in extensions and p.is_file()
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _loaders() -> list[tuple[str, callable]]:
        """Return ``(extension, loader_function)`` pairs in priority order."""
        loaders: list[tuple[str, callable]] = []
        try:
            import joblib

            loaders.append((".joblib", joblib.load))
        except ImportError:
            pass

        def _load_pickle(path: str) -> object:
            with open(path, "rb") as fh:
                return pickle.load(fh)  # noqa: S301

        loaders.append((".pkl", _load_pickle))
        return loaders
