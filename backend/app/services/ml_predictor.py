"""
Local ML predictor that loads models directly from ml/exports/.
Replaces the external BentoML service call with an in-process inference.

Class labels: 0=benign  1=phishing  2=malware  3=spam

Heavy ML packages (torch, transformers, xgboost) are imported lazily
inside MLPredictor.__init__ so that the FastAPI app can start normally
even when those packages are absent from the environment.
"""

import logging
import pickle
import sys
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Project root — used to put ml.src on sys.path at import time
# (the actual heavy imports are deferred to MLPredictor.__init__)
_PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

CLASS_NAMES = ["benign", "phishing", "malware", "spam"]


class MLPredictor:
    """
    In-process ML predictor:
      1. Tokenises URL with DistilBERT tokenizer (NLP branch)
      2. Extracts 23 lexical features (numerical branch)
      3. Runs through PhishScamSenseFusionModel to get fused embeddings
      4. Classifies with XGBoost (4-class: benign/phishing/malware/spam)
    """

    def __init__(self, exports_dir: Path) -> None:
        logger.info("Loading ML models from %s", exports_dir)

        # Lazy imports — keeps FastAPI startable even without ML packages
        import numpy as np  # noqa: F401 (stored on self below)
        import torch
        from ml.src.features.url_features import extract_url_features
        from ml.src.models.fusion_model import PhishScamSenseFusionModel
        from ml.src.models.nlp_branch import URLTokenizer

        # Keep references so predict() doesn't need to re-import
        self._np = np
        self._torch = torch
        self._extract_url_features = extract_url_features

        # --- Fusion model (PyTorch state dict) ---
        fusion_path = exports_dir / "fusion_model.pt"
        state_dict = torch.load(
            fusion_path,
            map_location="cpu",
            weights_only=True,
        )
        self.fusion_model = PhishScamSenseFusionModel()
        self.fusion_model.load_state_dict(state_dict)
        self.fusion_model.eval()

        # --- XGBoost classifier (pickle — avoids sklearn tag compat issue) ---
        xgb_path = exports_dir / "xgb_classifier.pkl"
        with open(xgb_path, "rb") as f:
            self.xgb_classifier = pickle.load(f)

        # --- DistilBERT tokenizer ---
        self.tokenizer = URLTokenizer()

        logger.info("ML models loaded successfully")

    def predict(self, url: str) -> dict:
        """
        Predict threat class for a URL.

        Returns:
            {
                "phishing":    bool   – True for any non-benign class
                "confidence":  float  – probability of the predicted class
                "label":       int    – 0-3
                "threat_type": str    – "benign" | "phishing" | "malware" | "spam"
                "features":    dict   – 23 lexical features extracted from the URL
            }
        """
        torch = self._torch
        np = self._np

        tokens = self.tokenizer.tokenize([url])
        features = self._extract_url_features(url)
        numerical = torch.tensor([list(features.values())], dtype=torch.float32)

        with torch.no_grad():
            fused = self.fusion_model(
                tokens["input_ids"],
                tokens["attention_mask"],
                numerical,
            )

        proba = self.xgb_classifier.predict_proba(fused.cpu().numpy())[0]
        pred_class = int(np.argmax(proba))

        return {
            "phishing": pred_class != 0,
            "confidence": float(proba[pred_class]),
            "label": pred_class,
            "threat_type": CLASS_NAMES[pred_class],
            "features": features,
        }


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_predictor: Optional[MLPredictor] = None


def get_predictor(exports_dir: Optional[Path] = None) -> Optional[MLPredictor]:
    """Return the global predictor, initialising it if *exports_dir* is given."""
    global _predictor
    if _predictor is None and exports_dir is not None:
        _predictor = MLPredictor(exports_dir)
    return _predictor


def set_predictor(predictor: Optional[MLPredictor]) -> None:
    """Override the global predictor (used in tests to inject a mock)."""
    global _predictor
    _predictor = predictor
