"""Optional ML fallback: a pixel-based AI-generated-image classifier.

Loads a fine-tuned Keras model (transfer learning, MobileNetV2 on a real-vs-AI
dataset) and returns the probability that an image is AI-generated.  Unlike the
rule-based provenance detector (which reads metadata), this works from the
PIXELS, so it can flag AI images even after metadata has been stripped.

It is a SUPPORTING signal, not proof.  If TensorFlow or the model file is
absent, detection simply disables itself (returns None) and ForenSight runs
normally on its rule-based signals - exactly like the optional TSK / allocation
feature.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Optional

from . import config
from .logging_config import get_logger


def _model_img_size(model) -> tuple:
    """Read the image size the model expects from its input shape."""
    try:
        _, h, w, _ = model.input_shape          # (None, H, W, 3)
        if h and w:
            return (int(h), int(w))
    except Exception:  # noqa: BLE001
        pass
    return (128, 128)


@lru_cache(maxsize=1)
def _load_model():
    """Load the Keras model once (cached).  Returns None if unavailable."""
    logger = get_logger()
    try:
        import tensorflow as tf  # noqa: F401 - heavy, imported lazily
    except Exception:  # noqa: BLE001 - TF not installed
        logger.info("ML detector disabled: TensorFlow not installed.")
        return None
    path = Path(config.ML_MODEL_PATH)
    if not path.exists():
        logger.info("ML detector disabled: model file not found (%s).", path)
        return None
    try:
        import tensorflow as tf
        model = tf.keras.models.load_model(str(path))
        logger.info("ML detector loaded: %s", path.name)
        return model
    except Exception as exc:  # noqa: BLE001
        logger.warning("ML detector failed to load: %s", exc)
        return None


def available() -> bool:
    """True if the ML classifier is usable (TF installed + model present)."""
    return _load_model() is not None


def predict_ai_probability(image_path: str | Path) -> Optional[float]:
    """Return P(AI-generated) in [0, 1], or None if the ML fallback is off.

    The model outputs P(REAL); AI probability is 1 - P(REAL).
    """
    model = _load_model()
    if model is None:
        return None
    try:
        import tensorflow as tf
        img = tf.keras.utils.load_img(image_path, target_size=_model_img_size(model))
        arr = tf.keras.utils.img_to_array(img)[None, ...]
        p_real = float(model.predict(arr, verbose=0)[0][0])
        return max(0.0, min(1.0, 1.0 - p_real))
    except Exception as exc:  # noqa: BLE001 - undecodable image etc.
        get_logger().warning("ML prediction failed for %s: %s", image_path, exc)
        return None
