#!/usr/bin/env python3
"""
analysis/plot_summary_dashboard.py

Generates Figure 13: a 6-panel dashboard summarizing detection rate,
FPR/FNR, CPU/memory overhead, and detection latency across all
experiment configurations.

Run:
    python3 analysis/plot_summary_dashboard.py
"""
import csv
import os
import statistics
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detection"))
from entropy_detector import load_rows, confusion_at_threshold, metrics  # noqa: E402

SUMMARY_PATH = os.path.join(os.path.dirname(__file__), "..", "results", "experiment_summary.csv")
CALIBRATION_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "calibration_flows.csv")
OUT_PATH = os.path.join(os.path.dirname(__file__), "..", "results", "plots", "fig13_summary_dashboard.png")
OPERATING_THRESHOLD = 2.5


def main():
    with open(SUMMARY_PATH) as f:
        rows = list(csv.DictReader(f))

    configs, det_means, cpu_means, mem_means, lat_means = [], [], [], [], []
    for at in ["syn", "udp"]:
        for it in ["low", "medium", "high"]:
            vals = [r for r in rows if r["attack_type"] == at and r["intensity"] == it]
            configs.append(f"{at.upper()}\n{it.capitalize()}")
            det_means.append(statistics.mean(float(r["detection_rate_pct"]) for r in vals))
            cpu_means.append(statistics.mean(float(r["avg_cpu_pct"]) for r in vals))
            mem_means.append(statistics.mean(float(r["avg_mem_mb"]) for r in vals))
            lat_means.append(statistics.mean(float(r["detection_latency_ms"]) for r in vals))

    # real FPR/FNR from the actual calibration sweep at the chosen operating threshold
    cal_rows, _ = load_rows(CALIBRATION_PATH)
    TP, FP, TN, FN = confusion_at_threshold(cal_rows, OPERATING_THRESHOLD)
    acc, prec, rec, f1, fpr, fnr = metrics(TP, FP, TN, FN)

    x = np.arange(len(configs))
    colors_b = ["#2563EB", "#3B82F6", "#60A5FA", "#22c55e", "#4ADE80", "#86EFAC"]

    fig = plt.figure(figsize=(14, 8.5))
    fig.suptitle("Complete Performance Evaluation -- All 6 Metrics", fontsize=14, fontweight="bold")

    ax1 = fig.add_subplot(2, 3, 1)
    ax1.bar(x, det_means, color=colors_b)
    ax1.set_title("Detection Rate (%)")
    ax1.set_xticks(x)
    ax1.set_xticklabels(configs, fontsize=7)
    ax1.set_ylim(0, 110)
    ax1.grid(True, alpha=0.3, axis="y")

    ax2 = fig.add_subplot(2, 3, 2)
    ax2.bar([0, 1], [fpr * 100, fnr * 100], color=["#ef4444", "#f59e0b"])
    ax2.set_xticks([0, 1])
    ax2.set_xticklabels(["FPR", "FNR"])
    ax2.set_title(f"Error Rates @ threshold={OPERATING_THRESHOLD} bits")
    ax2.set_ylabel("%")
    ax2.set_ylim(0, max(10, fpr * 100, fnr * 100) + 5)
    ax2.grid(True, alpha=0.3, axis="y")

    ax3 = fig.add_subplot(2, 3, 3)
    ax3.bar(x, lat_means, color=colors_b)
    ax3.set_title("Detection Latency (ms)")
    ax3.set_xticks(x)
    ax3.set_xticklabels(configs, fontsize=7)
    ax3.grid(True, alpha=0.3, axis="y")

    ax4 = fig.add_subplot(2, 3, 4)
    ax4.bar(x, cpu_means, color=colors_b)
    ax4.set_title("Avg Controller CPU (%)")
    ax4.set_xticks(x)
    ax4.set_xticklabels(configs, fontsize=7)
    ax4.grid(True, alpha=0.3, axis="y")

    ax5 = fig.add_subplot(2, 3, 5)
    ax5.bar(x, mem_means, color=colors_b)
    ax5.set_title("Avg Controller Memory (MB)")
    ax5.set_xticks(x)
    ax5.set_xticklabels(configs, fontsize=7)
    ax5.grid(True, alpha=0.3, axis="y")

    ax6 = fig.add_subplot(2, 3, 6)
    ax6.bar(["Accuracy", "Precision", "Recall", "F1"],
            [acc * 100, prec * 100, rec * 100, f1 * 100],
            color=["#2563EB", "#22c55e", "#f59e0b", "#8b5cf6"])
    ax6.set_title("Calibration Metrics (%)")
    ax6.set_ylim(0, 110)
    ax6.grid(True, alpha=0.3, axis="y")

    fig.tight_layout(rect=[0, 0, 1, 0.96])

    os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
    plt.savefig(OUT_PATH, dpi=180, bbox_inches="tight")
    plt.close()
    print(f"Saved: {OUT_PATH}")


if __name__ == "__main__":
    main()
