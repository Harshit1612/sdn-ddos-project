#!/usr/bin/env python3
"""
analysis/plot_calibration.py

Generates the two calibration figures from the build guide:
  Figure 3 -- Threshold sweep (accuracy / F1 / FPR / FNR vs entropy threshold)
  Figure 4 -- Confusion matrix at a chosen operating threshold

Reuses the real functions from detection/entropy_detector.py so the numbers
in the plots match exactly what --sweep prints on the command line.

Run:
    python3 analysis/plot_calibration.py --input data/calibration_flows.csv --threshold 2.5
"""
import argparse
import os
import sys

import matplotlib
matplotlib.use("Agg")  # no GUI needed -- just saves PNG files to disk
import matplotlib.pyplot as plt
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detection"))
from entropy_detector import load_rows, confusion_at_threshold, metrics  # noqa: E402

OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "results", "plots")


def plot_sweep(rows, out_path):
    thresholds = [round(t * 0.25, 2) for t in range(2, 19)]  # 0.5 .. 4.5
    accs, f1s, fprs, fnrs = [], [], [], []
    best_thresh, best_f1 = None, -1

    for t in thresholds:
        TP, FP, TN, FN = confusion_at_threshold(rows, t)
        acc, prec, rec, f1, fpr, fnr = metrics(TP, FP, TN, FN)
        accs.append(acc * 100)
        f1s.append(f1 * 100)
        fprs.append(fpr * 100)
        fnrs.append(fnr * 100)
        if f1 > best_f1:
            best_f1, best_thresh = f1, t

    plt.figure(figsize=(9, 6))
    plt.plot(thresholds, accs, marker="o", label="Accuracy (%)", color="tab:blue")
    plt.plot(thresholds, f1s, marker="s", label="F1 Score (%)", color="tab:green")
    plt.plot(thresholds, fprs, marker="^", label="FPR (%)", color="tab:red")
    plt.plot(thresholds, fnrs, marker="d", label="FNR (%)", color="tab:purple")
    plt.axvline(best_thresh, color="orange", linestyle="--",
                label=f"Best F1 threshold = {best_thresh} bits")
    plt.title("Detection Performance vs Entropy Threshold (window-based sweep)")
    plt.xlabel("Entropy Threshold (bits)")
    plt.ylabel("Score (%)")
    plt.legend()
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()
    print(f"Saved: {out_path}")
    return best_thresh


def plot_confusion(rows, thresh, out_path):
    TP, FP, TN, FN = confusion_at_threshold(rows, thresh)
    acc, prec, rec, f1, fpr, fnr = metrics(TP, FP, TN, FN)

    matrix = np.array([[TP, FN], [FP, TN]])
    labels = [["TP\n(Attack correctly detected)", "FN\n(Attack missed)"],
              ["FP\n(Benign blocked)", "TN\n(Benign correctly passed)"]]

    fig, ax = plt.subplots(figsize=(7, 6))
    im = ax.imshow(matrix, cmap="RdYlGn_r", vmin=0)

    for i in range(2):
        for j in range(2):
            ax.text(j, i, f"{matrix[i, j]}\n{labels[i][j]}",
                     ha="center", va="center", fontsize=10,
                     color="white" if matrix[i, j] > matrix.max() / 2 else "black")

    ax.set_xticks([0, 1])
    ax.set_yticks([0, 1])
    ax.set_xticklabels(["Predicted\nATTACK", "Predicted\nBENIGN"])
    ax.set_yticklabels(["Actual\nATTACK", "Actual\nBENIGN"])
    ax.set_title(
        f"Confusion Matrix | Threshold={thresh} bits (window-based)\n"
        f"Acc={acc:.3f} Prec={prec:.3f} Rec={rec:.3f} F1={f1:.3f} FNR={fnr:.3f}"
    )
    fig.colorbar(im, ax=ax, label="Window count")
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()
    print(f"Saved: {out_path}")


def main():
    parser = argparse.ArgumentParser(description="Generate calibration figures (sweep + confusion matrix)")
    parser.add_argument("--input", required=True, help="calibration CSV path")
    parser.add_argument("--threshold", type=float, default=2.5,
                         help="operating threshold for the confusion matrix (default 2.5)")
    args = parser.parse_args()

    os.makedirs(OUT_DIR, exist_ok=True)
    rows, source = load_rows(args.input)
    if source == "synthetic":
        print("NOTE: synthetic fallback dataset used, not real CICDDoS2019.")

    sweep_path = os.path.join(OUT_DIR, "figure3_threshold_sweep.png")
    confusion_path = os.path.join(OUT_DIR, "figure4_confusion_matrix.png")

    best_thresh = plot_sweep(rows, sweep_path)
    plot_confusion(rows, args.threshold, confusion_path)

    print(f"\nBest F1 threshold from sweep: {best_thresh} bits")
    print(f"Confusion matrix generated at your chosen operating threshold: {args.threshold} bits")


if __name__ == "__main__":
    main()
