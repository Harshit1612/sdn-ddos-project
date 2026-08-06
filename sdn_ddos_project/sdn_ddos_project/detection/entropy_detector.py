#!/usr/bin/env python3
import argparse
import collections
import csv
import math

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
        print(f"Loaded {len(rows_raw)} flows from {path} (synthetic calibration schema -- fallback path)")
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

    raise ValueError(f"Could not find recognisable src-IP/label columns in {path}. Found columns: {fieldnames}")


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
    fpr = FP / (FP + TN) if (FP + TN) else 0
    fnr = FN / (FN + TP) if (FN + TP) else 0
    return acc, prec, rec, f1, fpr, fnr


def sweep(rows):
    thresholds = [round(t * 0.25, 2) for t in range(2, 19)]
    best = None
    for thresh in thresholds:
        TP, FP, TN, FN = confusion_at_threshold(rows, thresh)
        acc, prec, rec, f1, fpr, fnr = metrics(TP, FP, TN, FN)
        print(f"thresh={thresh:5.2f}  acc={acc*100:6.2f}%  f1={f1*100:6.2f}%  "
              f"fpr={fpr*100:6.2f}%  fnr={fnr*100:6.2f}%")
        if best is None or f1 > best[1]:
            best = (thresh, f1, fpr, fnr)
    print()
    print(f"Best threshold: {best[0]} bits | F1={best[1]*100:.1f}% | FPR={best[2]*100:.1f}% | FNR={best[3]*100:.1f}%")
    return best[0]


def main():
    parser = argparse.ArgumentParser(description="Entropy-based DDoS detector (offline)")
    parser.add_argument("--input", default="data/CICDDoS2019_subset.csv",
                         help="calibration CSV path (defaults to the CICDDoS2019 subset)")
    parser.add_argument("--sweep", action="store_true", help="run threshold sweep")
    parser.add_argument("--threshold", type=float, default=2.5, help="single-shot threshold")
    args = parser.parse_args()

    rows, source = load_rows(args.input)
    if source == "synthetic":
        print("NOTE: this run used the SYNTHETIC fallback dataset, not the real "
              "CICDDoS2019 dataset. State this accurately in the report.")

    if args.sweep:
        sweep(rows)
    else:
        src_ctr = collections.Counter(r["src_ip"] for r in rows)
        h = shannon_entropy(src_ctr)
        alarm = h < args.threshold
        print(f"Entropy H(src_ip) = {h:.4f} bits")
        print("ALERT: DDoS suspected" if alarm else "OK: traffic looks benign")


if __name__ == "__main__":
    main()
