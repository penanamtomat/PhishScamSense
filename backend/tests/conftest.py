"""
Shared pytest fixtures for PhishScamSense backend tests.

The ML predictor is mocked so tests run without loading the 268 MB models.
"""

import pytest
from fastapi.testclient import TestClient
from unittest.mock import MagicMock

from app.main import app
import app.services.ml_predictor as ml_predictor_module

# ---------------------------------------------------------------------------
# Default mock prediction results
# ---------------------------------------------------------------------------

MOCK_PHISHING_RESULT = {
    "phishing": True,
    "confidence": 0.95,
    "label": 1,
    "threat_type": "phishing",
    "features": {
        "url_length": 60,
        "hostname_length": 30,
        "path_length": 20,
        "num_dots": 3,
        "num_hyphens": 2,
        "num_underscores": 0,
        "num_slashes": 3,
        "num_query_params": 1,
        "num_fragments": 0,
        "num_digits": 4,
        "num_special_chars": 5,
        "url_entropy": 4.2,
        "hostname_entropy": 3.8,
        "has_ip_address": 0,
        "has_punycode": 0,
        "has_port": 0,
        "has_https": 0,
        "has_at_symbol": 0,
        "has_double_slash_redirect": 0,
        "subdomain_count": 1,
        "tld_length": 3,
        "consecutive_consonants_max": 4,
        "vowel_ratio": 0.35,
    },
}

MOCK_BENIGN_RESULT = {
    "phishing": False,
    "confidence": 0.98,
    "label": 0,
    "threat_type": "benign",
    "features": {
        "url_length": 22,
        "hostname_length": 10,
        "path_length": 0,
        "num_dots": 2,
        "num_hyphens": 0,
        "num_underscores": 0,
        "num_slashes": 2,
        "num_query_params": 0,
        "num_fragments": 0,
        "num_digits": 0,
        "num_special_chars": 1,
        "url_entropy": 3.6,
        "hostname_entropy": 3.1,
        "has_ip_address": 0,
        "has_punycode": 0,
        "has_port": 0,
        "has_https": 1,
        "has_at_symbol": 0,
        "has_double_slash_redirect": 0,
        "subdomain_count": 1,
        "tld_length": 3,
        "consecutive_consonants_max": 3,
        "vowel_ratio": 0.42,
    },
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_predictor():
    """A MagicMock that mimics MLPredictor, defaulting to a phishing result."""
    predictor = MagicMock()
    predictor.predict.return_value = MOCK_PHISHING_RESULT.copy()
    return predictor


@pytest.fixture
def client(mock_predictor):
    """TestClient with the global predictor replaced by a mock."""
    ml_predictor_module.set_predictor(mock_predictor)
    with TestClient(app) as c:
        yield c
    ml_predictor_module.set_predictor(None)


@pytest.fixture
def client_no_model():
    """TestClient with no predictor loaded (simulates model not ready)."""
    ml_predictor_module.set_predictor(None)
    with TestClient(app) as c:
        yield c
