"""
Unit tests for app.services.ml_predictor and ml.src.features.url_features.

These tests do NOT load the actual PyTorch / XGBoost models.
MLPredictor itself is tested via a mock; the feature extractor is tested
directly since it has no heavy dependencies.
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import numpy as np
import pytest
import torch

# Ensure project root on path (mirrors what ml_predictor.py does)
_PROJECT_ROOT = Path(__file__).resolve().parents[3]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from ml.src.features.url_features import extract_url_features


# ---------------------------------------------------------------------------
# extract_url_features
# ---------------------------------------------------------------------------


class TestExtractUrlFeatures:
    def test_returns_23_features(self):
        features = extract_url_features("https://www.example.com/path?q=1")
        assert len(features) == 23

    def test_feature_keys_present(self):
        features = extract_url_features("https://example.com")
        expected_keys = {
            "url_length", "hostname_length", "path_length",
            "num_dots", "num_hyphens", "num_underscores", "num_slashes",
            "num_query_params", "num_fragments", "num_digits", "num_special_chars",
            "url_entropy", "hostname_entropy",
            "has_ip_address", "has_punycode", "has_port", "has_https",
            "has_at_symbol", "has_double_slash_redirect",
            "subdomain_count", "tld_length",
            "consecutive_consonants_max", "vowel_ratio",
        }
        assert expected_keys == set(features.keys())

    def test_https_flag(self):
        assert extract_url_features("https://example.com")["has_https"] == 1
        assert extract_url_features("http://example.com")["has_https"] == 0

    def test_ip_address_detection(self):
        assert extract_url_features("http://192.168.1.1/page")["has_ip_address"] == 1
        assert extract_url_features("https://example.com")["has_ip_address"] == 0

    def test_url_length(self):
        url = "https://example.com"
        features = extract_url_features(url)
        assert features["url_length"] == len(url)

    def test_dot_count(self):
        assert extract_url_features("https://sub.example.co.uk/path")["num_dots"] == 3

    def test_hyphen_count(self):
        assert extract_url_features("https://my-site-login.com")["num_hyphens"] == 2

    def test_at_symbol(self):
        assert extract_url_features("http://user@evil.com")["has_at_symbol"] == 1
        assert extract_url_features("https://safe.com")["has_at_symbol"] == 0

    def test_subdomain_count(self):
        assert extract_url_features("https://a.b.example.com")["subdomain_count"] == 2
        assert extract_url_features("https://example.com")["subdomain_count"] == 0

    def test_non_standard_port(self):
        assert extract_url_features("http://example.com:8080/path")["has_port"] == 1
        assert extract_url_features("https://example.com:443/path")["has_port"] == 0

    def test_query_params(self):
        assert extract_url_features("https://example.com/p?a=1&b=2")["num_query_params"] == 2
        assert extract_url_features("https://example.com")["num_query_params"] == 0

    def test_entropy_is_positive(self):
        features = extract_url_features("https://example.com")
        assert features["url_entropy"] > 0
        assert features["hostname_entropy"] > 0

    def test_vowel_ratio_range(self):
        ratio = extract_url_features("https://example.com")["vowel_ratio"]
        assert 0.0 <= ratio <= 1.0

    def test_empty_path_length(self):
        assert extract_url_features("https://example.com")["path_length"] == 0

    def test_punycode_detection(self):
        assert extract_url_features("https://xn--p1ai.com")["has_punycode"] == 1
        assert extract_url_features("https://example.com")["has_punycode"] == 0

    def test_digits_count(self):
        assert extract_url_features("https://site123.com/path456")["num_digits"] == 6

    def test_all_values_are_numeric(self):
        features = extract_url_features("https://www.example.com/path?x=1")
        for key, val in features.items():
            assert isinstance(val, (int, float)), f"{key} is not numeric: {val}"


# ---------------------------------------------------------------------------
# MLPredictor (constructor + predict) — mocked heavy dependencies
# ---------------------------------------------------------------------------


class TestMLPredictorInit:
    def test_loads_models_from_exports_dir(self, tmp_path):
        """MLPredictor.__init__ loads fusion_model.pt via torch and xgb_classifier.pkl via pickle."""
        fusion_path = tmp_path / "fusion_model.pt"
        xgb_path = tmp_path / "xgb_classifier.pkl"
        fusion_path.touch()
        xgb_path.touch()

        mock_xgb_instance = MagicMock()

        with (
            patch("app.services.ml_predictor.torch.load") as mock_torch_load,
            patch("app.services.ml_predictor.PhishScamSenseFusionModel") as mock_fusion_cls,
            patch("app.services.ml_predictor.pickle.load", return_value=mock_xgb_instance),
            patch("app.services.ml_predictor.URLTokenizer"),
        ):
            mock_fusion = MagicMock()
            mock_fusion_cls.return_value = mock_fusion
            mock_torch_load.return_value = {}

            from app.services.ml_predictor import MLPredictor
            predictor = MLPredictor(tmp_path)

            mock_torch_load.assert_called_once()
            mock_fusion.load_state_dict.assert_called_once_with({})
            mock_fusion.eval.assert_called_once()
            assert predictor.xgb_classifier is mock_xgb_instance


class TestMLPredictorPredict:
    @pytest.fixture
    def predictor(self, tmp_path):
        """Return a fully mocked MLPredictor instance (no file I/O)."""
        fusion_path = tmp_path / "fusion_model.pt"
        xgb_path = tmp_path / "xgb_classifier.pkl"
        fusion_path.touch()
        xgb_path.touch()

        mock_xgb = MagicMock()
        mock_xgb.predict_proba.return_value = np.array([[0.05, 0.90, 0.03, 0.02]])

        with (
            patch("app.services.ml_predictor.torch.load", return_value={}),
            patch("app.services.ml_predictor.PhishScamSenseFusionModel") as mock_fusion_cls,
            patch("app.services.ml_predictor.pickle.load", return_value=mock_xgb),
            patch("app.services.ml_predictor.URLTokenizer") as mock_tokenizer_cls,
            patch("app.services.ml_predictor.extract_url_features") as mock_features,
        ):
            # Fusion model returns a (1, 192) tensor
            mock_fusion = MagicMock()
            mock_fusion.return_value = torch.zeros(1, 192)
            mock_fusion_cls.return_value = mock_fusion

            # Tokenizer returns dummy tensors
            mock_tokenizer = MagicMock()
            mock_tokenizer.tokenize.return_value = {
                "input_ids": torch.zeros(1, 10, dtype=torch.long),
                "attention_mask": torch.ones(1, 10, dtype=torch.long),
            }
            mock_tokenizer_cls.return_value = mock_tokenizer

            # Feature extractor returns 23 zero features
            mock_features.return_value = {f"feat_{i}": 0.0 for i in range(23)}

            from app.services.ml_predictor import MLPredictor
            inst = MLPredictor(tmp_path)
            # Bind the mocked extract_url_features so assertions work
            inst._mock_features = mock_features
            yield inst

    def test_predict_returns_all_fields(self, predictor):
        result = predictor.predict("http://phish.example.com")
        assert {"phishing", "confidence", "label", "threat_type", "features"} == set(result.keys())

    def test_predict_phishing_class(self, predictor):
        result = predictor.predict("http://phish.example.com")
        assert result["phishing"] is True
        assert result["label"] == 1
        assert result["threat_type"] == "phishing"

    def test_predict_confidence_is_float(self, predictor):
        result = predictor.predict("http://phish.example.com")
        assert isinstance(result["confidence"], float)
        assert 0.0 <= result["confidence"] <= 1.0

    def test_predict_benign_class(self, predictor):
        predictor.xgb_classifier.predict_proba.return_value = np.array([[0.97, 0.01, 0.01, 0.01]])
        result = predictor.predict("https://google.com")
        assert result["phishing"] is False
        assert result["label"] == 0
        assert result["threat_type"] == "benign"

    def test_predict_malware_class(self, predictor):
        predictor.xgb_classifier.predict_proba.return_value = np.array([[0.03, 0.04, 0.91, 0.02]])
        result = predictor.predict("http://malware.example.com")
        assert result["phishing"] is True
        assert result["label"] == 2
        assert result["threat_type"] == "malware"

    def test_predict_spam_class(self, predictor):
        predictor.xgb_classifier.predict_proba.return_value = np.array([[0.05, 0.05, 0.05, 0.85]])
        result = predictor.predict("http://spam.example.com")
        assert result["phishing"] is True
        assert result["label"] == 3
        assert result["threat_type"] == "spam"

    def test_features_dict_returned(self, predictor):
        result = predictor.predict("https://example.com")
        assert isinstance(result["features"], dict)
        assert len(result["features"]) == 23


# ---------------------------------------------------------------------------
# get_predictor / set_predictor singleton helpers
# ---------------------------------------------------------------------------


class TestPredictorSingleton:
    def setup_method(self):
        import app.services.ml_predictor as m
        m.set_predictor(None)

    def teardown_method(self):
        import app.services.ml_predictor as m
        m.set_predictor(None)

    def test_get_predictor_returns_none_when_not_set(self):
        import app.services.ml_predictor as m
        assert m.get_predictor() is None

    def test_set_predictor_persists(self):
        import app.services.ml_predictor as m
        mock = MagicMock()
        m.set_predictor(mock)
        assert m.get_predictor() is mock

    def test_get_predictor_initialises_when_dir_given(self, tmp_path):
        import app.services.ml_predictor as m
        with patch.object(m, "MLPredictor") as mock_cls:
            mock_instance = MagicMock()
            mock_cls.return_value = mock_instance
            result = m.get_predictor(tmp_path)
        assert result is mock_instance

    def test_get_predictor_does_not_reinitialise(self, tmp_path):
        import app.services.ml_predictor as m
        existing = MagicMock()
        m.set_predictor(existing)
        with patch.object(m, "MLPredictor") as mock_cls:
            result = m.get_predictor(tmp_path)
        mock_cls.assert_not_called()
        assert result is existing
