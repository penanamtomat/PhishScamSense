"""
Validation-set product tests.

Loads the URL column from data/raw/validation.csv and sends every URL
through the POST /api/v1/predict endpoint (ML predictor is mocked so
this runs without loading the heavy models).

The tests verify:
  1. Every URL produces a valid 200 response.
  2. The response schema matches PredictionResponse for each URL.
  3. Confidence is always in [0, 1].
  4. label/threat_type are always coherent (label 0 → benign, else phishing=True).
"""

import csv
from pathlib import Path
from unittest.mock import MagicMock

import pytest

import app.services.ml_predictor as ml_predictor_module
from fastapi.testclient import TestClient
from app.main import app

# ---------------------------------------------------------------------------
# Load validation URLs
# ---------------------------------------------------------------------------

_VALIDATION_CSV = Path(__file__).resolve().parents[3] / "PhishScamSense" / "data" / "raw" / "validation.csv"

CLASS_NAMES = ["benign", "phishing", "malware", "spam"]


def _load_validation_urls() -> list[tuple[str, int]]:
    """Return list of (url, true_label) from validation.csv."""
    rows = []
    with open(_VALIDATION_CSV, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            url = row["URL"].strip()
            label = int(row["ClassLabel"])
            if url:
                rows.append((url, label))
    return rows


_VALIDATION_ROWS = _load_validation_urls()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def validation_client():
    """
    TestClient with a mock predictor that returns deterministic results
    based on the last character of the URL (cycles through all 4 classes).
    """

    def _side_effect(url: str) -> dict:
        # Cycle through classes based on URL hash for determinism
        cls = hash(url) % 4
        return {
            "phishing": cls != 0,
            "confidence": 0.80 + (cls * 0.05),
            "label": cls,
            "threat_type": CLASS_NAMES[cls],
            "features": {"url_length": len(url)},
        }

    mock = MagicMock()
    mock.predict.side_effect = _side_effect
    ml_predictor_module.set_predictor(mock)

    with TestClient(app) as c:
        yield c

    ml_predictor_module.set_predictor(None)


# ---------------------------------------------------------------------------
# Parametrized validation tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("url,true_label", _VALIDATION_ROWS)
def test_validation_url_returns_200(validation_client, url, true_label):
    """Every validation URL must produce a 200 response."""
    resp = validation_client.post("/api/v1/predict", json={"url": url})
    assert resp.status_code == 200, f"URL={url!r} returned {resp.status_code}: {resp.text}"


@pytest.mark.parametrize("url,true_label", _VALIDATION_ROWS)
def test_validation_response_schema(validation_client, url, true_label):
    """Response must contain all required fields with correct types."""
    resp = validation_client.post("/api/v1/predict", json={"url": url})
    body = resp.json()

    assert isinstance(body["phishing"], bool), f"phishing field not bool for {url!r}"
    assert isinstance(body["confidence"], float), f"confidence field not float for {url!r}"
    assert isinstance(body["label"], int), f"label field not int for {url!r}"
    assert isinstance(body["threat_type"], str), f"threat_type field not str for {url!r}"


@pytest.mark.parametrize("url,true_label", _VALIDATION_ROWS)
def test_validation_confidence_range(validation_client, url, true_label):
    """Confidence score must be in [0.0, 1.0]."""
    body = validation_client.post("/api/v1/predict", json={"url": url}).json()
    assert 0.0 <= body["confidence"] <= 1.0, (
        f"confidence={body['confidence']} out of range for {url!r}"
    )


@pytest.mark.parametrize("url,true_label", _VALIDATION_ROWS)
def test_validation_label_threat_type_coherent(validation_client, url, true_label):
    """label and threat_type must be consistent; label=0 ↔ phishing=False."""
    body = validation_client.post("/api/v1/predict", json={"url": url}).json()

    assert 0 <= body["label"] <= 3, f"label {body['label']} out of range for {url!r}"
    assert body["threat_type"] == CLASS_NAMES[body["label"]], (
        f"threat_type mismatch: label={body['label']}, threat_type={body['threat_type']!r}"
    )
    if body["label"] == 0:
        assert body["phishing"] is False, f"phishing should be False for benign URL {url!r}"
    else:
        assert body["phishing"] is True, f"phishing should be True for {body['threat_type']} URL {url!r}"


# ---------------------------------------------------------------------------
# Aggregate summary test (runs once, provides overview)
# ---------------------------------------------------------------------------


def test_validation_all_urls_processed(validation_client):
    """Smoke test: all validation URLs process without error, print a summary."""
    results = {"benign": 0, "phishing": 0, "malware": 0, "spam": 0, "errors": 0}

    for url, _ in _VALIDATION_ROWS:
        resp = validation_client.post("/api/v1/predict", json={"url": url})
        if resp.status_code == 200:
            results[resp.json()["threat_type"]] += 1
        else:
            results["errors"] += 1

    total = len(_VALIDATION_ROWS)
    print(f"\nValidation summary ({total} URLs):")
    for k, v in results.items():
        pct = v / total * 100 if total > 0 else 0
        print(f"  {k:<10}: {v:>4}  ({pct:.1f}%)")

    assert results["errors"] == 0, f"{results['errors']} URLs failed to process"
