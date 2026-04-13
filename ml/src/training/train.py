"""
Training pipeline for PhishScamSense.

Two training modes:
  xgboost  — Extract URL lexical features → XGBoost (fast, no GPU required)
  neural   — DistilBERT + BiLSTM + MLP → fused embeddings → XGBoost (GPU recommended)

Usage:
  # From project root:
  python -m ml.src.training.train --mode xgboost --data-dir data/raw --output-dir models
  python -m ml.src.training.train --mode neural  --data-dir data/raw --output-dir models --epochs 5

Labels: 0=benign  1=phishing  2=malware  3=spam
"""

import argparse
import json
import logging
import sys
from datetime import datetime
from pathlib import Path

import numpy as np
import xgboost as xgb
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split

from ml.src.data.data_loader import load_cic_bell_dns2021, load_feedback_data
from ml.src.features.feature_extractor import extract_features

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

CLASS_NAMES = ["benign", "phishing", "malware", "spam"]


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

def extract_features_batch(urls: list[str], fetch_content: bool = False) -> np.ndarray:
    """
    Extract 88 features for a list of URLs.

    fetch_content=False (default): URL-only features (fast, no network I/O).
      Content features are all 0; external features are all 0/-1.
    fetch_content=True: fetches each page and computes content + DNS features
      (very slow — use only when building a page-content training dataset).
    """
    from ml.src.features.feature_extractor import FEATURE_COUNT
    logger.info(f"Extracting features for {len(urls):,} URLs…")
    rows = []
    for i, url in enumerate(urls):
        try:
            feat = extract_features(url, html=None, compute_external=False)
            rows.append(list(feat.values()))
        except Exception:
            rows.append([0.0] * FEATURE_COUNT)
        if (i + 1) % 25_000 == 0:
            logger.info(f"  {i + 1:,}/{len(urls):,}")
    return np.array(rows, dtype=np.float32)


# ---------------------------------------------------------------------------
# XGBoost-only training
# ---------------------------------------------------------------------------

def train_xgboost_only(
    X_train: np.ndarray,
    y_train: np.ndarray,
    X_val: np.ndarray,
    y_val: np.ndarray,
) -> xgb.XGBClassifier:
    """Train XGBoost on raw URL features (no neural network)."""
    logger.info("Training XGBoost classifier…")
    clf = xgb.XGBClassifier(
        n_estimators=500,
        max_depth=6,
        learning_rate=0.1,
        objective="multi:softmax",
        num_class=4,
        eval_metric="mlogloss",
        early_stopping_rounds=15,
        n_jobs=-1,
    )
    clf.fit(
        X_train, y_train,
        eval_set=[(X_val, y_val)],
        verbose=50,
    )
    return clf


# ---------------------------------------------------------------------------
# Neural pipeline training
# ---------------------------------------------------------------------------

def _tokenize_in_batches(tokenizer, urls: list[str], chunk: int = 512):
    """Tokenize URLs in chunks to avoid OOM on large lists."""
    import torch
    all_ids, all_masks = [], []
    for i in range(0, len(urls), chunk):
        batch = urls[i : i + chunk]
        enc = tokenizer.tokenize(batch)
        all_ids.append(enc["input_ids"])
        all_masks.append(enc["attention_mask"])
    return torch.cat(all_ids, dim=0), torch.cat(all_masks, dim=0)


def train_neural_pipeline(
    urls_train: list[str],
    y_train: np.ndarray,
    urls_val: list[str],
    y_val: np.ndarray,
    epochs: int,
    batch_size: int,
    lr: float,
):
    """Train DistilBERT+BiLSTM+MLP fusion model then XGBoost on fused embeddings."""
    import torch
    from torch.utils.data import DataLoader, TensorDataset

    from ml.src.models.fusion_model import PhishScamSenseFusionModel
    from ml.src.models.nlp_branch import URLTokenizer

    device = "cuda" if torch.cuda.is_available() else "cpu"
    logger.info(f"Using device: {device}")

    tokenizer = URLTokenizer(max_length=128)

    # Numerical features
    X_train_num = extract_features_batch(urls_train)
    X_val_num = extract_features_batch(urls_val)
    input_dim = X_train_num.shape[1]

    fusion_model = PhishScamSenseFusionModel(num_features=input_dim).to(device)
    classifier_head = torch.nn.Linear(fusion_model.fusion_dim, 4).to(device)
    optimizer = torch.optim.Adam(
        list(fusion_model.parameters()) + list(classifier_head.parameters()),
        lr=lr,
    )
    criterion = torch.nn.CrossEntropyLoss()

    # Tokenize training set
    logger.info("Tokenizing training URLs…")
    input_ids_train, mask_train = _tokenize_in_batches(tokenizer, urls_train)

    dataset = TensorDataset(
        input_ids_train,
        mask_train,
        torch.tensor(X_train_num, dtype=torch.float32),
        torch.tensor(y_train, dtype=torch.long),
    )
    loader = DataLoader(dataset, batch_size=batch_size, shuffle=True, pin_memory=(device == "cuda"))

    # Training loop
    for epoch in range(epochs):
        fusion_model.train()
        classifier_head.train()
        total_loss = 0.0
        for ids, mask, num_feat, lbls in loader:
            ids = ids.to(device)
            mask = mask.to(device)
            num_feat = num_feat.to(device)
            lbls = lbls.to(device)

            optimizer.zero_grad()
            fused = fusion_model(ids, mask, num_feat)
            logits = classifier_head(fused)
            loss = criterion(logits, lbls)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()

        avg_loss = total_loss / len(loader)
        logger.info(f"Epoch {epoch + 1}/{epochs}  loss={avg_loss:.4f}")

    # Extract embeddings for XGBoost training
    fusion_model.eval()
    logger.info("Extracting fused embeddings for XGBoost…")

    logger.info("  Tokenizing validation URLs…")
    input_ids_val, mask_val = _tokenize_in_batches(tokenizer, urls_val)

    def embed(ids, mask, num_feat):
        chunks = []
        bs = 128
        for i in range(0, ids.shape[0], bs):
            with torch.no_grad():
                out = fusion_model(
                    ids[i : i + bs].to(device),
                    mask[i : i + bs].to(device),
                    num_feat[i : i + bs].to(device),
                )
            chunks.append(out.cpu().numpy())
        return np.vstack(chunks)

    train_emb = embed(input_ids_train, mask_train, torch.tensor(X_train_num))
    val_emb = embed(input_ids_val, mask_val, torch.tensor(X_val_num))

    logger.info("Training XGBoost on fused embeddings…")
    clf = xgb.XGBClassifier(
        n_estimators=300,
        max_depth=6,
        learning_rate=0.1,
        objective="multi:softmax",
        num_class=4,
        eval_metric="mlogloss",
        early_stopping_rounds=10,
        n_jobs=-1,
    )
    clf.fit(train_emb, y_train, eval_set=[(val_emb, y_val)], verbose=50)

    return fusion_model, clf, input_dim


# ---------------------------------------------------------------------------
# Model saving
# ---------------------------------------------------------------------------

def save_artifacts(output_dir: Path, mode: str, **artifacts) -> dict:
    """Save model artifacts and metadata; return paths dict."""
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    saved: dict[str, str] = {}

    if mode == "xgboost":
        # Save as native XGBoost JSON (avoids pickle cross-version warnings)
        json_stamp = output_dir / f"xgb_classifier_{ts}.json"
        json_active = output_dir / "xgb_classifier.json"
        artifacts["clf"].save_model(str(json_stamp))
        artifacts["clf"].save_model(str(json_active))
        logger.info(f"Saved XGBoost model → {json_stamp}")
        saved["xgb_classifier"] = str(json_stamp)

        # Remove stale fusion model so ml_predictor uses xgboost-only mode
        stale_fusion = output_dir / "fusion_model.pt"
        if stale_fusion.exists():
            stale_fusion.rename(output_dir / f"fusion_model_archived_{ts}.pt")
            logger.info("Archived stale fusion model (xgboost-only mode active)")

    else:  # neural
        import torch

        fusion_stamp = output_dir / f"fusion_model_{ts}.pt"
        fusion_latest = output_dir / "fusion_model_latest.pt"
        fusion_canonical = output_dir / "fusion_model.pt"
        xgb_stamp = output_dir / f"xgb_classifier_{ts}.json"
        xgb_latest = output_dir / "xgb_classifier_latest.json"
        xgb_canonical = output_dir / "xgb_classifier.json"

        torch.save(artifacts["fusion_model"].state_dict(), fusion_stamp)
        torch.save(artifacts["fusion_model"].state_dict(), fusion_latest)
        torch.save(artifacts["fusion_model"].state_dict(), fusion_canonical)
        artifacts["clf"].save_model(str(xgb_stamp))
        artifacts["clf"].save_model(str(xgb_latest))
        artifacts["clf"].save_model(str(xgb_canonical))

        # Remove stale XGBoost JSON model (from xgboost-only training)
        # to avoid the predictor loading the wrong model.
        stale_json = output_dir / "xgb_classifier.json"
        if stale_json.exists():
            stale_json.rename(output_dir / f"xgb_classifier_archived_{ts}.json")
            logger.info("Archived stale xgb_classifier.json (neural mode active)")

        logger.info(f"Saved fusion model → {fusion_stamp}")
        logger.info(f"Saved XGBoost model → {xgb_stamp}")
        saved["fusion_model"] = str(fusion_stamp)
        saved["xgb_classifier"] = str(xgb_stamp)

    meta = {
        "mode": mode,
        "timestamp": ts,
        "classes": CLASS_NAMES,
        "label_map": {name: i for i, name in enumerate(CLASS_NAMES)},
        "num_features": artifacts.get("num_features"),
        "artifacts": saved,
    }
    meta_path = output_dir / "model_info.json"
    with open(meta_path, "w") as f:
        json.dump(meta, f, indent=2)
    logger.info(f"Saved metadata → {meta_path}")
    return saved


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def parse_args():
    p = argparse.ArgumentParser(description="Train PhishScamSense model on CIC-Bell-DNS2021")
    p.add_argument("--data-dir", default="data/raw", help="Directory with CIC CSV files")
    p.add_argument("--output-dir", default="models", help="Where to save trained models")
    p.add_argument(
        "--mode",
        choices=["xgboost", "neural"],
        default="xgboost",
        help="xgboost: fast, URL features only | neural: full DistilBERT pipeline",
    )
    p.add_argument(
        "--max-benign",
        type=int,
        default=100_000,
        help="Max benign samples to load (0 = all ~988k; training will be slow)",
    )
    p.add_argument(
        "--samples-per-class",
        type=int,
        default=0,
        help="Cap each class to this many samples for balanced training (0 = no cap)",
    )
    p.add_argument("--test-size", type=float, default=0.15, help="Fraction for test set")
    p.add_argument("--val-size", type=float, default=0.10, help="Fraction for validation set")
    p.add_argument("--epochs", type=int, default=5, help="Neural training epochs")
    p.add_argument("--batch-size", type=int, default=32, help="Neural training batch size")
    p.add_argument("--lr", type=float, default=1e-4, help="Neural learning rate")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument(
        "--feedback-dir",
        default="data/feedback",
        help="Directory with feedback CSVs (url,label) to merge into training set "
             "(default: data/feedback). Set to '' to disable.",
    )
    return p.parse_args()


def _balance_dataset(
    urls: list[str],
    labels: list[int],
    samples_per_class: int,
    seed: int,
) -> tuple[list[str], list[int]]:
    """Subsample each class to at most *samples_per_class* entries."""
    import random
    rng = random.Random(seed)
    per_class: dict[int, list[str]] = {}
    for url, lbl in zip(urls, labels):
        per_class.setdefault(lbl, []).append(url)
    balanced_urls, balanced_labels = [], []
    for lbl, url_list in sorted(per_class.items()):
        sample = rng.sample(url_list, min(samples_per_class, len(url_list)))
        balanced_urls.extend(sample)
        balanced_labels.extend([lbl] * len(sample))
        logger.info(f"  {CLASS_NAMES[lbl]:12s}: {len(sample):,} (from {len(url_list):,})")
    return balanced_urls, balanced_labels


def main():
    args = parse_args()
    max_benign = args.max_benign if args.max_benign > 0 else None

    # ---- Load dataset -------------------------------------------------------
    logger.info("Loading CIC-Bell-DNS2021 dataset…")
    urls_all, labels_all = load_cic_bell_dns2021(
        args.data_dir, max_benign=max_benign, seed=args.seed
    )
    if not urls_all:
        logger.error("No data loaded — check --data-dir path.")
        sys.exit(1)

    # ---- Merge feedback (false-positive corrections, etc.) ------------------
    if args.feedback_dir:
        fb_urls, fb_labels = load_feedback_data(args.feedback_dir)
        if fb_urls:
            # Repeat feedback samples to give them more weight during training.
            # A small feedback set (e.g. 13 URLs) would otherwise be lost in a
            # 100k-sample dataset. Repeating 10x makes each FP correction ~0.1%
            # of the dataset — enough to shift the decision boundary without
            # distorting overall class distributions.
            FEEDBACK_REPEAT = 10
            urls_all = urls_all + fb_urls * FEEDBACK_REPEAT
            labels_all = labels_all + fb_labels * FEEDBACK_REPEAT
            logger.info(
                f"Merged {len(fb_urls):,} feedback URLs "
                f"(repeated ×{FEEDBACK_REPEAT} → +{len(fb_urls) * FEEDBACK_REPEAT:,} rows)"
            )

    # ---- Optional per-class balance ----------------------------------------
    if args.samples_per_class > 0:
        logger.info(f"Balancing to {args.samples_per_class:,} samples per class…")
        urls_all, labels_all = _balance_dataset(
            urls_all, labels_all, args.samples_per_class, args.seed
        )

    urls_arr = np.array(urls_all, dtype=object)
    y_arr = np.array(labels_all, dtype=np.int32)

    logger.info("Class distribution:")
    for i, name in enumerate(CLASS_NAMES):
        logger.info(f"  {name:12s}: {np.sum(y_arr == i):>8,}")

    # ---- Train / val / test split -------------------------------------------
    X_tr, X_test, y_tr, y_test = train_test_split(
        urls_arr, y_arr,
        test_size=args.test_size,
        random_state=args.seed,
        stratify=y_arr,
    )
    # val_size relative to train+val portion
    relative_val = args.val_size / (1.0 - args.test_size)
    X_train, X_val, y_train, y_val = train_test_split(
        X_tr, y_tr,
        test_size=relative_val,
        random_state=args.seed,
        stratify=y_tr,
    )
    logger.info(f"Split → train={len(X_train):,}  val={len(X_val):,}  test={len(X_test):,}")

    output_dir = Path(args.output_dir)

    # ---- Train --------------------------------------------------------------
    if args.mode == "xgboost":
        X_train_feat = extract_features_batch(X_train.tolist())
        X_val_feat = extract_features_batch(X_val.tolist())
        X_test_feat = extract_features_batch(X_test.tolist())

        clf = train_xgboost_only(X_train_feat, y_train, X_val_feat, y_val)

        y_pred = clf.predict(X_test_feat)
        logger.info("\nTest-set results:\n" + classification_report(
            y_test, y_pred, target_names=CLASS_NAMES, digits=4
        ))

        save_artifacts(
            output_dir, "xgboost",
            clf=clf,
            num_features=X_train_feat.shape[1],
        )

    else:  # neural
        fusion_model, clf, num_features = train_neural_pipeline(
            X_train.tolist(), y_train,
            X_val.tolist(), y_val,
            epochs=args.epochs,
            batch_size=args.batch_size,
            lr=args.lr,
        )

        # Evaluate on test set
        import torch
        from ml.src.models.nlp_branch import URLTokenizer

        device = "cuda" if torch.cuda.is_available() else "cpu"
        tokenizer = URLTokenizer(max_length=128)
        X_test_feat = extract_features_batch(X_test.tolist())
        ids_test, mask_test = _tokenize_in_batches(tokenizer, X_test.tolist())

        fusion_model.eval()
        chunks = []
        bs = 128
        for i in range(0, ids_test.shape[0], bs):
            with torch.no_grad():
                out = fusion_model(
                    ids_test[i : i + bs].to(device),
                    mask_test[i : i + bs].to(device),
                    torch.tensor(X_test_feat[i : i + bs]).to(device),
                )
            chunks.append(out.cpu().numpy())
        test_emb = np.vstack(chunks)

        y_pred = clf.predict(test_emb)
        logger.info("\nTest-set results:\n" + classification_report(
            y_test, y_pred, target_names=CLASS_NAMES, digits=4
        ))

        save_artifacts(
            output_dir, "neural",
            fusion_model=fusion_model,
            clf=clf,
            num_features=num_features,
        )

    logger.info("Done.")


if __name__ == "__main__":
    main()
