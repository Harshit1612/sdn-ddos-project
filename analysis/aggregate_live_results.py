#!/usr/bin/env python3
"""
analysis/aggregate_live_results.py

Second half of the Problem-2 fix: after scripts/run_experiment_matrix.py has
been run on a real Mininet/Ryu testbed, this script slices the controller's
continuous results/metrics_poll{1,2,5}s_*.csv streams by the timestamps in
results/run_log.csv, computes REAL per-run detection_rate_pct,
detection_latency_ms, avg_cpu_pct, avg_mem_mb, avg_entropy, and joins in the
REAL iperf3 Mbps readings from results/throughput_log.csv -- producing a
results/experiment_summary.csv with the exact same column schema the
fig5/fig6/fig11/fig13 plotting code (from the build guide) already expects,
so those figures do not need to be rewritten -- just re-run against real data.

Run (on the testbed, after run_experiment_matrix.py finishes):
  python3 analysis/aggregate_live_results.py \
      --results-dir results --out results/experiment_summary.csv
"""
import argparse
import csv
import glob
import os
import re
from collections import defaultdict
from datetime import datetime


def load_metrics_by_poll(results_dir):
    """Loads every results/metrics_poll{P}s_*.csv into {poll: [rows...]}."""
    by_poll = {}
    for path in glob.glob(os.path.join(results_dir, "metrics_poll*s_*.csv")):
        m = re.search(r"metrics_poll(\d+)s_", os.path.basename(path))
        if not m:
            continue
        poll = int(m.group(1))
        with open(path) as f:
            rows = list(csv.DictReader(f))
        by_poll.setdefault(poll, []).extend(rows)
    for poll in by_poll:
        by_poll[poll].sort(key=lambda r: r["timestamp"])
    return by_poll


def load_run_log(results_dir):
    path = os.path.join(results_dir, "run_log.csv")
    with open(path) as f:
        return list(csv.DictReader(f))


def load_throughput(results_dir):
    path = os.path.join(results_dir, "throughput_log.csv")
    by_run = defaultdict(dict)
    with open(path) as f:
        for r in csv.DictReader(f):
            key = (r["attack_type"], r["intensity"], int(r["poll_interval"]), int(r["rep"]))
            try:
                mbps = float(r["mbps"])
            except (TypeError, ValueError):
                mbps = None
            by_run[key][r["phase"]] = mbps
    return by_run


def slice_window(metrics_rows, start_ts, end_ts):
    start = datetime.fromisoformat(start_ts)
    end = datetime.fromisoformat(end_ts)
    return [r for r in metrics_rows
            if start <= datetime.fromisoformat(r["timestamp"]) <= end]


def summarize_window(window_rows):
    if not window_rows:
        return None
    n = len(window_rows)
    detect_flags = [int(r["detection_flag"]) for r in window_rows]
    detection_rate_pct = 100.0 * sum(detect_flags) / n
    cpu_vals = [float(r["cpu_pct"]) for r in window_rows if r["cpu_pct"] != ""]
    mem_vals = [float(r["mem_mb"]) for r in window_rows if r["mem_mb"] != ""]
    entropy_vals = [float(r["entropy"]) for r in window_rows if r["entropy"] != ""]
    latency_vals = [float(r["detection_latency_ms"]) for r in window_rows
                     if r.get("detection_latency_ms")]
    return {
        "detection_rate_pct": round(detection_rate_pct, 2),
        "avg_cpu_pct": round(sum(cpu_vals) / len(cpu_vals), 2) if cpu_vals else "",
        "avg_mem_mb": round(sum(mem_vals) / len(mem_vals), 2) if mem_vals else "",
        "avg_entropy": round(sum(entropy_vals) / len(entropy_vals), 3) if entropy_vals else "",
        # first detection is the real "time-to-first-mitigation" for this run
        "detection_latency_ms": round(latency_vals[0], 2) if latency_vals else "",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--results-dir", default="results")
    parser.add_argument("--out", default="results/experiment_summary.csv")
    args = parser.parse_args()

    metrics_by_poll = load_metrics_by_poll(args.results_dir)
    run_log = load_run_log(args.results_dir)
    throughput = load_throughput(args.results_dir)

    out_rows = []
    for i, run in enumerate(run_log, start=1):
        poll = int(run["poll_interval"])
        rep = int(run["rep"])
        atype = run["attack_type"]
        intensity = run["intensity"]

        metrics_rows = metrics_by_poll.get(poll, [])
        window = slice_window(metrics_rows, run["start_ts"], run["end_ts"])
        summary = summarize_window(window)
        if summary is None:
            print(f"WARNING: no metrics rows found for run {i} "
                  f"({atype}/{intensity}/poll{poll}/rep{rep}) -- skipping")
            continue

        tp = throughput.get((atype, intensity, poll, rep), {})
        out_rows.append({
            "run_id": i,
            "attack_type": atype,
            "intensity": intensity,
            "poll_interval": poll,
            "rep": rep,
            "detection_rate_pct": summary["detection_rate_pct"],
            "detection_latency_ms": summary["detection_latency_ms"],
            "avg_cpu_pct": summary["avg_cpu_pct"],
            "avg_mem_mb": summary["avg_mem_mb"],
            "avg_entropy": summary["avg_entropy"],
            "throughput_baseline_mbps": tp.get("baseline", ""),
            "throughput_during_mbps": tp.get("during", ""),
            "throughput_post_mbps": tp.get("post", ""),
        })

    if not out_rows:
        raise SystemExit("No runs could be summarized -- check run_log.csv and metrics_poll*.csv exist.")

    with open(args.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(out_rows[0].keys()))
        w.writeheader()
        w.writerows(out_rows)

    print(f"Wrote {len(out_rows)} REAL runs (from live Mininet/Ryu capture) to {args.out}")
    print("Re-run the fig5/fig6/fig11/fig13 plotting code from the build guide against this file "
          "to get genuine latency/throughput/CPU/memory figures.")


if __name__ == "__main__":
    main()
