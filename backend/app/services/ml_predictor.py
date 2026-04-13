"""
Local ML predictor that loads models directly from ml/exports/.
Replaces the external BentoML service call with an in-process inference.

Class labels: 0=benign  1=phishing  2=malware  3=spam

Heavy ML packages (torch, transformers, xgboost) are imported lazily
inside MLPredictor.__init__ so that the FastAPI app can start normally
even when those packages are absent from the environment.
"""

import hashlib
import logging
import pickle
import sys
import warnings
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Project root — used to put ml.src on sys.path at import time
# (the actual heavy imports are deferred to MLPredictor.__init__)
_PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from ml.src.features.whitelist import is_whitelisted  # noqa: E402

CLASS_NAMES = ["benign", "phishing", "malware", "spam"]

_CHECKSUM_FILE = "model_checksums.sha256"


def _compute_sha256(path: Path) -> str:
    """Return hex SHA-256 digest of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _verify_model_file(path: Path, exports_dir: Path) -> None:
    """
    Verify *path* against stored SHA-256 in model_checksums.sha256.

    - First run (no checksum file): records hash and warns operator to commit the file.
    - Subsequent runs: compares stored vs actual hash, raises RuntimeError on mismatch.
    """
    import json as _json
    checksum_path = Path("/app/data") / _CHECKSUM_FILE if Path("/app/data").exists() else Path(__file__).resolve().parent / _CHECKSUM_FILE
    checksums: dict = {}
    if checksum_path.exists():
        try:
            checksums = _json.loads(checksum_path.read_text())
        except Exception:
            checksums = {}
    file_key = path.name
    actual = _compute_sha256(path)
    if file_key not in checksums:
        checksums[file_key] = actual
        checksum_path.write_text(_json.dumps(checksums, indent=2))
        logger.warning(
            "Model checksum recorded for %s (%s). "
            "Commit %s to source control to enable tamper detection.",
            file_key, actual, _CHECKSUM_FILE,
        )
    elif checksums[file_key] != actual:
        raise RuntimeError(
            f"Model integrity check FAILED for {path.name}. "
            f"Expected {checksums[file_key]}, got {actual}. "
            "File may have been tampered with. Aborting."
        )
    else:
        logger.debug("Model integrity OK: %s", file_key)


class MLPredictor:
    """
    In-process ML predictor supporting two modes:

    Neural mode (fusion_model.pt present):
      1. Tokenises URL with DistilBERT tokenizer (NLP branch)
      2. Extracts 23 lexical features (numerical branch)
      3. Runs through PhishScamSenseFusionModel to get 192-dim fused embeddings
      4. Classifies with XGBoost (4-class: benign/phishing/malware/spam)

    XGBoost-only mode (fusion_model.pt absent):
      1. Extracts 23 lexical features
      2. Classifies directly with XGBoost (no neural network)
    """

    def __init__(self, exports_dir: Path) -> None:
        logger.info("Loading ML models from %s", exports_dir)

        # Lazy imports — keeps FastAPI startable even without ML packages
        import numpy as np  # noqa: F401 (stored on self below)
        from ml.src.features.feature_extractor import extract_features

        self._np = np
        self._extract_features = extract_features

        # --- XGBoost classifier ---
        # Use native Booster (no sklearn dependency) to avoid XGBoost/sklearn
        # version-compatibility issues with pickle.
        import xgboost as xgb
        json_path = exports_dir / "xgb_classifier.json"
        pkl_path  = exports_dir / "xgb_classifier.pkl"
        if json_path.exists():
            _verify_model_file(json_path, exports_dir)
            booster = xgb.Booster()
            booster.load_model(str(json_path))
            self._xgb_booster = booster
            self.xgb_classifier = None   # not used in booster mode
            logger.info("Loaded XGBoost model from JSON (Booster)")
        elif pkl_path.exists():
            warnings.warn(
                "Loading XGBoost model from pickle is deprecated and insecure. "
                "Retrain with the latest train.py to generate .json format. "
                "Pickle support will be removed in a future version.",
                DeprecationWarning,
                stacklevel=2,
            )
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", category=UserWarning, module="xgboost")
                warnings.filterwarnings("ignore", category=FutureWarning)
                _verify_model_file(pkl_path, exports_dir)
            with open(pkl_path, "rb") as f:
                    self.xgb_classifier = pickle.load(f)  # noqa: S301
            self._xgb_booster = None
            logger.warning(
                "Loaded XGBoost model from INSECURE pickle format. "
                "Please retrain to generate .json format."
            )
        else:
            raise FileNotFoundError(f"No XGBoost model found in {exports_dir}")

        # --- Fusion model (only used when model_info.json says mode=neural) ---
        import json as _json
        _info_path = exports_dir / "model_info.json"
        _model_mode = "xgboost"
        if _info_path.exists():
            with open(_info_path) as _f:
                _model_mode = _json.load(_f).get("mode", "xgboost")

        fusion_path = exports_dir / "fusion_model.pt"
        if fusion_path.exists() and _model_mode == "neural":
            import torch
            from ml.src.models.fusion_model import PhishScamSenseFusionModel
            from ml.src.models.nlp_branch import URLTokenizer

            self._torch = torch
            _verify_model_file(fusion_path, exports_dir)
            state_dict = torch.load(fusion_path, map_location="cpu", weights_only=True)

            # Infer num_features from the checkpoint's first linear layer weight
            # to avoid relying on potentially stale model_info.json metadata.
            _first_weight = state_dict["numerical_branch.network.0.weight"]
            _num_features = _first_weight.shape[1]

            self.fusion_model = PhishScamSenseFusionModel(num_features=_num_features)
            self.fusion_model.load_state_dict(state_dict)
            self.fusion_model.eval()
            self.tokenizer = URLTokenizer()
            self._neural_mode = True
            self._num_features = _num_features
            logger.info("Neural pipeline loaded (DistilBERT + XGBoost, num_features=%d)", _num_features)
        else:
            self.fusion_model = None
            self.tokenizer = None
            self._neural_mode = False
            logger.info("XGBoost-only pipeline loaded (no fusion model)")

        logger.info("ML models loaded successfully")

    def predict(self, url: str, html: str | None = None) -> dict:
        """
        Predict threat class for a URL.

        Parameters
        ----------
        url:  The URL to classify.
        html: Optional raw HTML of the loaded page (sent by the browser extension).
              When provided, the 24 content-based features are extracted from the
              DOM, significantly improving detection of page-level phishing signals
              (invisible iframes, external form actions, missing page title, etc.).

        Returns
        -------
        {
            "phishing":    bool   — True for any non-benign class
            "confidence":  float  — probability of the predicted class
            "label":       int    — 0-3
            "threat_type": str    — "benign" | "phishing" | "malware" | "spam"
            "features":    dict   — 88 features extracted from the URL (+ HTML if provided)
        }
        """
        # Fast allowlist check — known top domains bypass ML entirely.
        # Matches on registrable domain label (e.g. "google" covers
        # google.com, mail.google.com, www.google.com/search?q=..., etc.)
        if is_whitelisted(url):
            return {
                "phishing": False,
                "confidence": 1.0,
                "label": 0,
                "threat_type": "benign",
                "features": {},
                "whitelisted": True,
            }

        np = self._np
        features = self._extract_features(url, html=html, compute_external=False)
        feat_values = list(features.values())

        if self._neural_mode:
            torch = self._torch
            tokens = self.tokenizer.tokenize([url])
            # The MLP branch expects exactly _num_features inputs (the first N
            # features from extract_url_features).  Content/external features
            # beyond this count are not part of the neural embedding and are
            # ignored by the MLP.
            numerical = torch.tensor(
                [feat_values[: self._num_features]], dtype=torch.float32
            )
            with torch.no_grad():
                fused = self.fusion_model(
                    tokens["input_ids"],
                    tokens["attention_mask"],
                    numerical,
                )
            input_features = fused.cpu().numpy()
        else:
            input_features = np.array([feat_values], dtype=np.float32)

        if self._xgb_booster is not None:
            import xgboost as xgb
            dmat = xgb.DMatrix(input_features)
            # output_margin=True gives raw logits; softmax → class probabilities
            margins = self._xgb_booster.predict(dmat, output_margin=True)  # (1, 4)
            e = np.exp(margins - margins.max(axis=1, keepdims=True))
            proba = (e / e.sum(axis=1, keepdims=True))[0]
        else:
            proba = self.xgb_classifier.predict_proba(input_features)[0]
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
