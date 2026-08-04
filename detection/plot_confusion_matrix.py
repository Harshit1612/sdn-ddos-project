#!/usr/bin/env python3
"""
detection/plot_confusion_matrix.py

Standalone confusion-matrix figure generator (Figure 4), styled to match
the expected report figure exactly: red/yellow/green quadrants, each cell
labeled with its count plus a plain-English description (e.g. "Attack
correctly detected"), and a title line summarising Accuracy / Precision /
Recall / F1 / FNR at the chosen threshold.

This is self-contained (does not import from entropy_detector.py) so it
can be run/tweaked independently.

Run:
    python3 detection/plot_confusion_matrix.py --input data/calibration_flows.csv --threshold 2.5
    python3 detection/plot_confusion_matrix.py --input data/calibration_flows.csv --threshold 2.5 --window-size 50 --output results/plots/fig4_confusion_matrix.png
"""
import argparse
import collections
import csv
import math
import os

import matplotlib.pyplot as plt
import numpy as np

CIC_SRC_IP_CANDIDATES = ["Source IP", " Source IP", "src_ip", "Src IP"]
CIC_LABEL_CANDIDATES = ["Label", " Label", "label"]
CIC_BENIGN_TOKENS = {"benign", "0", "normal"}


def shannon_entropy(counter):
    total = sum(counter.values())
    if not total:
        return 0.0
    return -sum((c / total) * math.log2(c / total) for c in counter.values() if c)


def _detect_column(fieldnames, candidates):
    for c in candidates:
        if c in fieldnames:
            return c
    return None


def load_rows(path):
    with open(path) as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames or []
        rows_raw = list(reader)

    if "src_ip" in fieldnames and "label" in fieldnames:
        print(f"Loaded {len(rows_raw)} flows from {path} (synthetic calibration schema)")
        return rows_raw, "synthetic"

    src_col = _detect_column(fieldnames, CIC_SRC_IP_CANDIDATES)
    label_col = _detect_column(fieldnames, CIC_LABEL_CANDIDATES)
    if src_col and label_col:
        normalised = []
        for r in rows_raw:
            label_raw = str(r.get(label_col, "")).strip().lower()
            label = "0" if label_raw in CIC_BENIGN_TOKENS else "1"
            normalised.append({"src_ip": r.get(src_col, "unknown"), "label": label})
        print(f"Loaded {len(normalised)} flows from {path} (real CICDDoS2019 export, "
              f"src column='{src_col}', label column='{label_col}')")
        return normalised, "cicddos2019"

    raise ValueError(
        f"Could not find recognisable src-IP/label columns in {path}. "
        f"Found columns: {fieldnames}"
    )


def make_windows(rows, window_size=50):
    windows = []
    for i in range(0, len(rows), window_size):
        chunk = rows[i:i + window_size]
        if not chunk:
            continue
        attack_frac = sum(int(r["label"]) for r in chunk) / len(chunk)
        window_label = 1 if attack_frac > 0.5 else 0
        windows.append((chunk, window_label))
    return windows


def confusion_at_threshold(rows, thresh, window_size=50):
    windows = make_windows(rows, window_size)
    TP = FP = TN = FN = 0
    for chunk, label in windows:
        src_ctr = collections.Counter(r["src_ip"] for r in chunk)
        h = shannon_entropy(src_ctr)
        alarm = h < thresh
        if alarm and label:
            TP += 1
        elif alarm and not label:
            FP += 1
        elif not alarm and not label:
            TN += 1
        else:
            FN += 1
    return TP, FP, TN, FN


def metrics(TP, FP, TN, FN):
    total = TP + FP + TN + FN
    acc = (TP + TN) / total if total else 0
    prec = TP / (TP + FP) if (TP + FP) else 0
    rec = TP / (TP + FN) if (TP + FN) else 0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0
    fnr = FN / (FN + TP) if (FN + TP) else 0
    return acc, prec, rec, f1, fnr


def plot_confusion_matrix(TP, FP, TN, FN, thresh, output_path):
    """Matches the expected figure: yellow = TP, red = FN/FP, green = TN,
    each cell labeled with count + description, title with full metrics."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    acc, prec, rec, f1, fnr = metrics(TP, FP, TN, FN)

    # grid layout: [row0: TP, FN] / [row1: FP, TN]
    # colors: TP=yellow, FN=red, FP=red, TN=green
    cell_colors = np.array([
        ["#F2D93B", "#B4131B"],
        ["#B4131B", "#1E9E4A"],
    ])
    cell_values = [[TP, FN], [FP, TN]]
    cell_labels = [
        ["Attack correctly\ndetected", "Attack\nmissed"],
        ["Benign\nblocked", "Benign correctly\npassed"],
    ]

    fig, ax = plt.subplots(figsize=(6, 5.5))
    ax.set_xlim(0, 2)
    ax.set_ylim(0, 2)
    ax.invert_yaxis()

    for i in range(2):
        for j in range(2):
            ax.add_patch(plt.Rectangle((j, i), 1, 1, color=cell_colors[i][j]))
            ax.text(j + 0.5, i + 0.38, str(cell_values[i][j]),
                    ha="center", va="center", fontsize=22, fontweight="bold",
                    color="black" if cell_colors[i][j] == "#F2D93B" else "white")
            ax.text(j + 0.5, i + 0.68, cell_labels[i][j],
                    ha="center", va="center", fontsize=10,
                    color="black" if cell_colors[i][j] == "#F2D93B" else "white")

    ax.set_xticks([0.5, 1.5])
    ax.set_xticklabels(["Predicted\nATTACK", "Predicted\nBENIGN"], fontsize=11)
    ax.set_yticks([0.5, 1.5])
    ax.set_yticklabels(["Actual\nATTACK", "Actual\nBENIGN"], fontsize=11)
    ax.tick_params(length=0)
    for spine in ax.spines.values():
        spine.set_visible(False)

    title = (f"Confusion Matrix | Threshold={thresh} bits (window-based)\n"
             f"Acc={acc:.3f} Prec={prec:.3f} Rec={rec:.3f} F1={f1:.3f} FNR={fnr:.3f}")
    ax.set_title(title, fontweight="bold", fontsize=12)

    fig.tight_layout()
    plt.savefig(output_path, dpi=180, bbox_inches="tight")
    plt.close()
    print(f"Saved: {output_path}")
    print(f"TP={TP} FP={FP} TN={TN} FN={FN} | Acc={acc:.3f} Prec={prec:.3f} "
          f"Rec={rec:.3f} F1={f1:.3f} FNR={fnr:.3f}")


def main():
    parser = argparse.ArgumentParser(description="Standalone confusion matrix (Figure 4) generator")
    parser.add_argument("--input", required=True, help="calibration CSV path")
    parser.add_argument("--threshold", type=float, default=2.5, help="entropy threshold (bits)")
    parser.add_argument("--window-size", type=int, default=50, help="flows per window")
    parser.add_argument("--output", default="results/plots/fig4_confusion_matrix.png",
                         help="where to save the PNG")
    args = parser.parse_args()

    rows, source = load_rows(args.input)
    if source == "synthetic":
        print("NOTE: this run used the SYNTHETIC fallback dataset, not the real "
              "CICDDoS2019 dataset. State this accurately in the report.")

    TP, FP, TN, FN = confusion_at_threshold(rows, args.threshold, window_size=args.window_size)

    if TP + FN == 0:
        print("\nWARNING: 0 actual-attack windows found in this data "
              "(no window had >50% attack-labeled rows).")
        print("The confusion matrix will show TP=0, FN=0 regardless of threshold.")
        print("This means the calibration CSV itself needs windows with a real "
              "attack-traffic majority -- check traffic/traffic_gen.py or try a "
              "smaller --window-size so attack bursts are more likely to dominate a window.\n")

    plot_confusion_matrix(TP, FP, TN, FN, args.threshold, args.output)


if __name__ == "__main__":
    main()
