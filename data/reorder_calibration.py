#!/usr/bin/env python3
"""
data/reorder_calibration.py

Fixes calibration_flows.csv so attack rows are grouped into one contiguous
burst (baseline -> attack -> recovery), rather than randomly scattered
throughout the file.

Why this matters: entropy_detector.py's make_windows() takes SEQUENTIAL
chunks of `window_size` rows and labels a window "attack" only if >50% of
its rows are attack-labeled. If attack rows are randomly interleaved at
low density (e.g. 33%), no sequential window will ever cross 50% by
chance -- so TP and FN stay at 0 regardless of threshold, no matter how
good the entropy signal actually is. Real DDoS traffic is bursty, not
uniformly scattered, so the calibration data should reflect that.

This script does NOT invent new rows -- it takes your existing 1200 rows
and re-sequences them: all label=0 rows first (baseline), then all
label=1 rows together (attack burst), then remaining label=0 rows
(recovery), roughly split 40/100/60 in proportion to what's available.

Run:
    python3 data/reorder_calibration.py --input data/calibration_flows.csv --output data/calibration_flows_ordered.csv
"""
import argparse
import csv


def main():
    parser = argparse.ArgumentParser(description="Reorder calibration CSV into baseline->attack->recovery blocks")
    parser.add_argument("--input", required=True, help="original calibration_flows.csv")
    parser.add_argument("--output", required=True, help="path to write the reordered CSV")
    args = parser.parse_args()

    with open(args.input) as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames
        rows = list(reader)

    benign = [r for r in rows if r["label"] == "0"]
    attack = [r for r in rows if r["label"] == "1"]

    print(f"Loaded {len(rows)} rows: {len(benign)} benign, {len(attack)} attack")

    # Split benign rows into a "baseline" chunk before the attack and a
    # "recovery" chunk after it, roughly 40% / 60% of the benign rows.
    split_point = int(len(benign) * 0.4)
    baseline = benign[:split_point]
    recovery = benign[split_point:]

    ordered = baseline + attack + recovery

    with open(args.output, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(ordered)

    print(f"Wrote {len(ordered)} rows to {args.output}")
    print(f"Structure: {len(baseline)} baseline (label=0) -> "
          f"{len(attack)} attack burst (label=1) -> "
          f"{len(recovery)} recovery (label=0)")
    print("\nNow re-run detection using this file, e.g.:")
    print(f"  python3 detection/entropy_detector.py --input {args.output} --sweep")
    print(f"  python3 detection/plot_confusion_matrix.py --input {args.output} --threshold 2.5")


if __name__ == "__main__":
    main()
