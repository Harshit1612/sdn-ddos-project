#!/usr/bin/env python3
"""
analysis/plot_roc_curve.py

Generates Figure 10: ROC curve for the entropy-based detector, computed
directly from detection/entropy_detector.py's confusion_at_threshold().

Run:
    python3 analysis/plot_roc_curve.py --input data/calibration_flows.csv
"""
import argparse
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detection"))
from entropy_detector import load_rows, confusion_at_threshold  # noqa: E402

OUT_PATH = os.path.join(os.path.dirname(__file__), "..", "results", "plots", "fig10_roc_curve.png")


def compute_roc(rows):
    # Ascending threshold order -- FPR/TPR are guaranteed non-decreasing
    # in this order, since a higher threshold can only ADD alarms, never
    # remove them. Do NOT re-sort by (fpr, tpr) tuples -- ties in fpr can
    # scramble that ordering and break the trapezoid-rule AUC calculation.
    thresholds = [round(t * 0.1, 1) for t in range(0, 50)]
    fprs, tprs = [], []
    for th in thresholds:
        TP, FP, TN, FN = confusion_at_threshold(rows, th)
        tprs.append(TP / (TP + FN) if (TP + FN) else 0.0)
        fprs.append(FP / (FP + TN) if (FP + TN) else 0.0)

    # Ensure curve starts at (0,0) and ends at (1,1) for a well-formed AUC
    fprs = [0.0] + fprs + [1.0]
    tprs = [0.0] + tprs + [1.0]

    auc = sum(
        (fprs[i] - fprs[i - 1]) * (tprs[i] + tprs[i - 1]) / 2
        for i in range(1, len(fprs))
    )
    return fprs, tprs, auc


def main():
    parser = argparse.ArgumentParser(description="Generate ROC curve (Figure 10)")
    parser.add_argument("--input", default="data/calibration_flows.csv")
    args = parser.parse_args()

    rows, source = load_rows(args.input)
    if source == "synthetic":
        print("NOTE: synthetic fallback dataset used, not real CICDDoS2019.")

    fprs, tprs, auc = compute_roc(rows)

    fig, ax = plt.subplots(figsize=(6.5, 6))
    ax.plot(fprs, tprs, "b-o", markersize=3, label=f"Entropy detector (AUC = {auc:.3f})")
    ax.plot([0, 1], [0, 1], "k--", alpha=0.5, label="Random classifier (AUC = 0.500)")
    ax.fill_between(fprs, tprs, alpha=0.08, color="blue")
    ax.set_xlabel("False Positive Rate (FPR)")
    ax.set_ylabel("True Positive Rate (TPR / Recall)")
    ax.set_title(f"ROC Curve -- Entropy-Based DDoS Detector\nAUC = {auc:.3f}", fontweight="bold")
    ax.legend()
    ax.grid(True, alpha=0.3)
    ax.set_xlim(-0.02, 1.02)
    ax.set_ylim(-0.02, 1.02)
    fig.tight_layout()

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    plt.savefig(OUT_PATH, dpi=180, bbox_inches="tight")
    plt.close()

    print(f"AUC = {auc:.4f}")
    print(f"Saved: {OUT_PATH}")


if __name__ == "__main__":
    main()
