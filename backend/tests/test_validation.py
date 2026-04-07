"""
Real-model validation tests against data/raw/validation.csv.

Loads the actual models from ml/exports/ and runs every URL through
MLPredictor.predict(), then reports accuracy, false positives, and
false negatives.

validation.csv label convention:
  ClassLabel=1  → benign
  ClassLabel=0  → malicious (phishing/malware/spam)

Model output convention:
  label=0  → benign   (phishing=False)
  label>0  → threat   (phishing=True)

Run with:
  cd backend
  python -m pytest tests/test_validation.py -v -s
"""

import csv
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_PROJECT_ROOT = Path(__file__).resolve().parents[3] / "PhishScamSense"
_EXPORTS_DIR = _PROJECT_ROOT / "ml" / "exports"
_VALIDATION_CSV = _PROJECT_ROOT / "data" / "raw" / "validation.csv"

if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


# ---------------------------------------------------------------------------
# Load validation data
# ---------------------------------------------------------------------------

def _load_validation_rows() -> list[tuple[str, bool]]:
    """
    Returns list of (url, is_malicious).
    CSV ClassLabel: 1=benign → is_malicious=False
                    0=malicious → is_malicious=True
    """
    rows = []
    with open(_VALIDATION_CSV, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            url = row["URL"].strip()
            if url:
                rows.append((url, row["ClassLabel"].strip() == "0"))
    return rows


_ROWS = _load_validation_rows()


# ---------------------------------------------------------------------------
# Fixture: real predictor (loaded once per session)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def real_predictor():
    """Load actual models from ml/exports/ — skipped if files are absent."""
    if not _EXPORTS_DIR.exists():
        pytest.skip(f"ml/exports/ not found at {_EXPORTS_DIR}")
    if not (_EXPORTS_DIR / "xgb_classifier.pkl").exists():
        pytest.skip("xgb_classifier.pkl not found in ml/exports/")

    from app.services.ml_predictor import MLPredictor
    return MLPredictor(_EXPORTS_DIR)


# ---------------------------------------------------------------------------
# Per-URL parametrized tests
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("url,is_malicious", _ROWS, ids=[r[0][:60] for r in _ROWS])
def test_url_prediction(real_predictor, url, is_malicious):
    """
    Each URL must return a valid prediction dict.
    Marks the test xfail if the prediction disagrees with the true label
    so the full run completes and you can see every discrepancy.
    """
    result = real_predictor.predict(url)

    # Schema checks always pass
    assert isinstance(result["phishing"], bool)
    assert isinstance(result["confidence"], float)
    assert 0.0 <= result["confidence"] <= 1.0
    assert result["label"] in (0, 1, 2, 3)
    assert result["threat_type"] in ("benign", "phishing", "malware", "spam")

    predicted_malicious = result["phishing"]   # True = model says threat
    correct = predicted_malicious == is_malicious

    true_label_str  = "malicious" if is_malicious      else "benign"
    pred_label_str  = result["threat_type"]
    conf            = result["confidence"]

    if not correct:
        kind = "FALSE_POSITIVE" if predicted_malicious else "FALSE_NEGATIVE"
        pytest.fail(
            f"[{kind}]  true={true_label_str}  pred={pred_label_str}({conf:.2%})  {url}"
        )


# ---------------------------------------------------------------------------
# Aggregate accuracy report (runs once, always passes, prints summary)
# ---------------------------------------------------------------------------

def test_validation_accuracy_report(real_predictor, capsys):
    """
    Runs all URLs, prints a full accuracy / FP / FN report.
    This test itself always passes — use the parametrized tests above
    to see individual failures.
    """
    total = len(_ROWS)
    correct = 0
    false_positives = []   # benign → predicted threat
    false_negatives = []   # malicious → predicted benign

    for url, is_malicious in _ROWS:
        result = real_predictor.predict(url)
        pred_threat = result["phishing"]

        if pred_threat == is_malicious:
            correct += 1
        elif pred_threat and not is_malicious:
            false_positives.append((url, result["threat_type"], result["confidence"]))
        else:
            false_negatives.append((url, result["threat_type"], result["confidence"]))

    accuracy = correct / total * 100
    fp_rate  = len(false_positives) / total * 100
    fn_rate  = len(false_negatives) / total * 100

    sep = "=" * 70
    with capsys.disabled():
        print(f"\n{sep}")
        print(f"  VALIDATION RESULTS  ({total} URLs)")
        print(sep)
        print(f"  Accuracy          : {correct}/{total}  ({accuracy:.2f}%)")
        print(f"  False Positives   : {len(false_positives)}  ({fp_rate:.2f}%)  benign -> predicted threat")
        print(f"  False Negatives   : {len(false_negatives)}  ({fn_rate:.2f}%)  malicious -> predicted benign")
        print(sep)

        if false_positives:
            print(f"\n  FALSE POSITIVES ({len(false_positives)}):")
            for url, threat_type, conf in false_positives:
                print(f"    [{threat_type} {conf:.2%}]  {url}")

        if false_negatives:
            print(f"\n  FALSE NEGATIVES ({len(false_negatives)}):")
            for url, threat_type, conf in false_negatives:
                print(f"    [benign {conf:.2%}]  {url}")

        print()

    # Always passes — report is informational
    assert accuracy >= 0
