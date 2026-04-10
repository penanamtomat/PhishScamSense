"""
Ingest false-positive feedback into the training pipeline.

Reads data/reports/false_positives.jsonl, collects every entry whose status is
'pending_review', labels those URLs as benign (label=0), appends them to
data/feedback/false_positives_benign.csv (deduplicating against existing rows),
and marks the processed entries as 'incorporated' back in the JSONL.

Usage (from project root):
    python scripts/ingest_false_positives.py
    python scripts/ingest_false_positives.py --fp-file data/reports/false_positives.jsonl \
        --out-csv data/feedback/false_positives_benign.csv

After running this script, retrain with:
    python -m ml.src.training.train --mode xgboost \
        --feedback-dir data/feedback --data-dir data/raw --output-dir models
    # or --mode neural for the full DistilBERT pipeline
"""

import argparse
import csv
import json
import logging
import sys
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

BENIGN_LABEL = 0


def load_jsonl(path: Path) -> list[dict]:
    entries = []
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError as e:
                logger.warning(f"Skipping malformed line {lineno}: {e}")
    return entries


def save_jsonl(path: Path, entries: list[dict]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for entry in entries:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")


def load_existing_urls(csv_path: Path) -> set[str]:
    """Return the set of URLs already in the feedback CSV."""
    if not csv_path.exists():
        return set()
    with open(csv_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return {row["url"] for row in reader}


def append_to_csv(csv_path: Path, new_rows: list[dict]) -> None:
    """Append rows (url, label) to the feedback CSV, creating it if needed."""
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    write_header = not csv_path.exists()
    with open(csv_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["url", "label"])
        if write_header:
            writer.writeheader()
        writer.writerows(new_rows)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Ingest false-positive URLs as benign training examples."
    )
    parser.add_argument(
        "--fp-file",
        default="data/reports/false_positives.jsonl",
        help="Path to the false_positives.jsonl file (default: data/reports/false_positives.jsonl)",
    )
    parser.add_argument(
        "--out-csv",
        default="data/feedback/false_positives_benign.csv",
        help="Destination CSV for benign feedback rows (default: data/feedback/false_positives_benign.csv)",
    )
    parser.add_argument(
        "--status-filter",
        default="pending_review",
        help="Only process entries whose status matches this value (default: pending_review)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be done without writing any files.",
    )
    args = parser.parse_args()

    fp_path = Path(args.fp_file)
    out_csv = Path(args.out_csv)

    if not fp_path.exists():
        logger.error(f"False-positive file not found: {fp_path}")
        sys.exit(1)

    # ── Load JSONL ────────────────────────────────────────────────────────────
    entries = load_jsonl(fp_path)
    logger.info(f"Loaded {len(entries)} entries from {fp_path}")

    pending = [e for e in entries if e.get("status") == args.status_filter]
    logger.info(f"Found {len(pending)} entries with status='{args.status_filter}'")

    if not pending:
        logger.info("Nothing to ingest. Exiting.")
        return

    # ── Deduplicate against existing CSV rows ─────────────────────────────────
    existing_urls = load_existing_urls(out_csv)
    logger.info(f"Existing feedback CSV has {len(existing_urls)} URLs")

    new_rows: list[dict] = []
    skipped_dupes = 0
    for entry in pending:
        url = entry.get("url", "").strip()
        if not url:
            logger.warning(f"Entry {entry.get('id')} has no URL — skipping")
            continue
        if url in existing_urls:
            logger.debug(f"Duplicate (already in CSV): {url}")
            skipped_dupes += 1
            continue
        new_rows.append({"url": url, "label": BENIGN_LABEL})
        existing_urls.add(url)

    logger.info(f"New rows to add: {len(new_rows)}  |  duplicates skipped: {skipped_dupes}")

    if not new_rows:
        logger.info("All pending entries were already in the feedback CSV. Nothing written.")
        # Still mark as incorporated so they don't reappear next run
    else:
        if args.dry_run:
            logger.info("[DRY RUN] Would append these URLs as benign:")
            for row in new_rows:
                logger.info(f"  {row['url']}")
        else:
            append_to_csv(out_csv, new_rows)
            logger.info(f"Appended {len(new_rows)} URLs → {out_csv}")

    # ── Mark processed entries as 'incorporated' in JSONL ────────────────────
    pending_ids = {e["id"] for e in pending}
    for entry in entries:
        if entry.get("id") in pending_ids:
            entry["status"] = "incorporated"

    if args.dry_run:
        logger.info("[DRY RUN] Would update JSONL statuses to 'incorporated'")
    else:
        save_jsonl(fp_path, entries)
        logger.info(f"Updated {len(pending_ids)} entries to status='incorporated' in {fp_path}")

    logger.info("Done. Next step: retrain the model with --feedback-dir data/feedback")


if __name__ == "__main__":
    main()
