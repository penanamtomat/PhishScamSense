# PhishScamSense

Real-time phishing URL detection via a browser extension backed by a local ML inference service.

## Overview

PhishScamSense detects phishing and spam URLs as you browse using a 4-class XGBoost classifier trained on the CIC-Bell-DNS2021 dataset. The browser extension checks every navigation against a local FastAPI backend that runs fully on-device — no data leaves your machine.

**Key capabilities:**
- Real-time URL classification on every page load (< 50 ms per prediction)
- 88-feature analysis: URL lexical structure, page content (HTML DOM), external signals (DNS/WHOIS)
- Domain allowlist — 585+ trusted domain labels + 46 institutional TLD suffix patterns (`.ac.id`, `.go.id`, `.edu`, `.gov`, etc.) bypass ML for instant benign response
- Typosquatting detection against 257 known brands via Levenshtein distance
- Suspicious TLD, shortening service, punycode, and IP-in-hostname detection
- Content-based signals when page HTML is available: external forms, null iframes, JS popups, unsafe anchors
- False positive reporting API — user-reported URLs saved to `data/reports/false_positives.jsonl`

---

## Architecture

```mermaid
graph LR
    Root[PhishScamSense] --> Backend[backend/]
    Root --> ML[ml/]
    Root --> Ext[extension/]
    Root --> Infra[infrastructure/]
    Root --> Data[data/]

    Backend --> B_App[app/]
    Backend --> B_Tests[tests/]
    B_App --> B_Api[api/routes/]
    B_App --> B_Core[core/]
    B_App --> B_Services[services/]
    B_App --> B_Workers[workers/]

    ML --> M_Notebooks[notebooks/]
    ML --> M_Src[src/]
    M_Src --> M_Features[features/]
    M_Src --> M_Models[models/]
    M_Src --> M_Training[training/]
    M_Src --> M_Data[data/]

    Ext --> E_Entry[entrypoints/]
    Ext --> E_Lib[lib/]
    E_Entry --> E_Popup[popup/]
```

### Request flow

```
Browser navigation
      │
      ▼
Extension (background.ts)
  └─ POST /api/v1/predict { url, html? }
              │
              ▼
       FastAPI Backend
              │
              ├─ Allowlist check (domain label + TLD suffix)  ──► benign immediately
              │
              ▼
       MLPredictor.predict()
        ├─ extract_features()   ← 88 features (URL + content + external)
        └─ XGBoost Booster.predict()
              │
              ▼
       { phishing, confidence, label, threat_type }
              │
      Extension shows warning / blocks page
```

---

## Project Structure

```
PhishScamSense/
├── backend/                  FastAPI inference service
│   ├── app/
│   │   ├── api/routes/       predict.py, reports.py, threats.py
│   │   ├── core/             config.py, lifespan, middleware
│   │   ├── schemas/          Pydantic request/response models
│   │   ├── services/         ml_predictor.py — model loading & inference
│   │   └── workers/          Celery stubs (future async tasks)
│   ├── tests/                pytest test suite
│   └── requirements.txt
│
├── ml/
│   ├── exports/              Active model files (xgb_classifier.json, etc.)
│   ├── notebooks/            Exploratory analysis
│   └── src/
│       ├── data/             data_loader.py — CIC-Bell-DNS2021 ingestion + augmentation
│       ├── features/
│       │   ├── url_features.py         57 URL-only features
│       │   ├── content_features.py     24 HTML DOM features
│       │   ├── external_features.py    7 DNS/WHOIS/HTTP features
│       │   ├── feature_extractor.py    Combined 88-feature entry point
│       │   └── whitelist.py            Domain allowlist (585 labels + 46 TLD suffixes)
│       ├── models/           fusion_model.py (neural pipeline, optional)
│       └── training/         train.py — XGBoost training pipeline
│
├── extension/                WXT (Vite) browser extension
│   ├── entrypoints/
│   │   ├── background.ts     Service worker — intercepts navigations
│   │   └── popup/            React UI popup
│   └── lib/                  Bloom filter, API client utilities
│
├── data/
│   ├── raw/                  CIC-Bell-DNS2021 CSVs + validation.csv (gitignored)
│   ├── processed/            (gitignored)
│   └── reports/              false_positives.jsonl — user-submitted reports (gitignored)
│
├── infrastructure/
│   └── airflow/              DAGs for scheduled retraining (planned)
│
└── docs/
    ├── prd                   Product Requirements Document
    └── architecture.md       Architecture diagrams
```

---

## Tech Stack

| Layer | Technology |
|---|---|
| Browser Extension | WXT Framework (Vite) + React + TypeScript + TailwindCSS |
| API | FastAPI + Pydantic + Uvicorn |
| ML Inference | XGBoost (Booster, JSON format) |
| Feature Extraction | tldextract (PSL), BeautifulSoup4, python-whois |
| Training Dataset | CIC-Bell-DNS2021 (benign / phishing / spam) |
| MLOps (planned) | MLflow + Apache Airflow |

---

## Feature Engineering

The classifier uses **88 features** grouped into three modules:

### URL features (57) — `ml/src/features/url_features.py`

| Group | Features | Count |
|---|---|---|
| Character counts | url_length, count_at, count_dollar, count_semicolumn, count_space, count_percentage, count_colon, count_star, count_or, count_tilde, count_http_token, count_comma, count_and, count_equal, count_question | 15 |
| Path-level | path_length, num_slashes, phish_hints_count, brand_in_path, has_path_extension, has_double_slash_redirect | 6 |
| Hostname numeric | hostname_length, num_dots, num_hyphens, num_underscores, num_digits_host, ratio_digits_host, num_digits_url, ratio_digits_url, url_entropy, hostname_entropy | 10 |
| Structural flags | has_ip_address, has_punycode, has_port, has_https, has_at_symbol, is_shortening_service, has_prefix_suffix, has_tld_in_path, has_tld_in_subdomain, has_abnormal_subdomain, has_suspicious_tld, char_repeat_count | 12 |
| Linguistic | consecutive_consonants_max, vowel_ratio, num_special_chars, has_statistical_report | 4 |
| Word-based | num_words, avg_word_length, max_word_length, min_word_length, subdomain_count | 5 |
| Brand / typosquatting | tld_length, domain_in_brand_exact, typosquatting_min_dist, typosquatting_suspicious, brand_in_subdomain | 5 |

### Content features (24) — `ml/src/features/content_features.py`
Extracted from raw HTML when provided by the browser extension. Default to 0 for URL-only analysis.

Internal/external hyperlink ratios, external CSS count, login form detection, external favicon, iframe visibility, JS popup/onmouseover/right-click disabling, empty title, domain-not-in-title, domain-not-in-copyright, form submission targets.

### External features (7) — `ml/src/features/external_features.py`
DNS record presence, domain age (days), registration length (days), WHOIS registered, redirect count, has_redirect, has_external_redirect. Disabled during training; enabled at inference optionally.

---

## Setup

### Prerequisites
- Python 3.11+
- Node.js 18+ (for extension)

### Backend

```bash
cd backend
python -m venv ../venv
source ../venv/Scripts/activate   # Windows: ..\venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Training

```bash
# Download CIC-Bell-DNS2021 CSVs into data/raw/
# Files needed: benign_domains.csv, phishing_domains.csv, spam_domains.csv

# Fast balanced training (recommended for development)
python -m ml.src.training.train \
  --mode xgboost \
  --data-dir data/raw \
  --output-dir ml/exports \
  --samples-per-class 16000

# Full dataset training
python -m ml.src.training.train \
  --mode xgboost \
  --data-dir data/raw \
  --output-dir ml/exports
```

Trained model is saved to `ml/exports/xgb_classifier.json` and loaded automatically by the backend on startup.

### Browser Extension

```bash
cd extension
npm install
npm run dev     # development with HMR
npm run build   # production build
```

Load the `extension/.output/chrome-mv3/` directory as an unpacked extension in Chrome.

---

## API

### `POST /api/v1/predict`

**Request:**
```json
{
  "url": "https://example.com/page",
  "html": "<html>...</html>"
}
```
`html` is optional — enables 24 content-based features when provided by the extension.

**Response:**
```json
{
  "phishing": false,
  "confidence": 0.98,
  "label": 0,
  "threat_type": "benign",
  "features": { ... }
}
```

Labels: `0` = benign, `1` = phishing, `2` = spam (internal), `3` = spam.
`phishing: true` for any non-benign label.
`features` is empty `{}` for allowlisted domains (fast path, no ML inference).

### `POST /api/v1/reports/false-positive`

**Request:**
```json
{
  "url": "https://flagged-site.com",
  "comments": "This is my company intranet"
}
```

**Response:**
```json
{
  "id": "uuid",
  "status": "received",
  "message": "Report saved. We will review this URL and update our detection."
}
```

Reports are persisted to `data/reports/false_positives.jsonl`.

---

## Testing

```bash
cd backend
pytest tests/ -v
```

The test suite covers:
- `test_ml_predictor.py` — feature extraction, MLPredictor init/predict, singleton helpers
- `test_validation.py` — end-to-end accuracy report against `data/raw/validation.csv`

---

## Model Performance

Current model (`xgb_classifier.json`, trained on CIC-Bell-DNS2021, balanced 16k/class):

| Class | Precision | Recall | F1 |
|---|---|---|---|
| benign | 0.96 | 0.99 | 0.98 |
| phishing | 0.99 | 0.94 | 0.97 |
| spam | 0.92 | 0.90 | 0.91 |
| **accuracy** | | | **0.98** |

---

## Roadmap

- [ ] Extension sends page HTML to backend for content-feature-based classification
- [ ] VirusTotal / Google Safe Browsing validation for false positive reports
- [ ] Scheduled Airflow DAG for weekly model retraining on fresh threat feeds
- [ ] MLflow experiment tracking integration
