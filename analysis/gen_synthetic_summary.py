#!/usr/bin/env python3
"""
analysis/gen_synthetic_summary.py

Generates a synthetic results/experiment_summary.csv covering the full
experiment matrix: attack_type x intensity x poll_interval, with all
columns needed by the analysis/plot_*.py scripts:

    run_id, attack_type, intensity, poll_interval,
    detection_rate_pct, detection_latency_ms, avg_entropy,
    avg_cpu_pct, avg_mem_mb

Replace with real measured values once you've run the full matrix on your
own testbed -- this is stand-in data only.
"""
import csv
import os
import random

random.seed(42)
OUT_PATH = os.path.join(os.path.dirname(__file__), "..", "results", "experiment_summary.csv")

BASE_STATS = {
    ("syn", "low"):    {"rate": 76, "latency": 3260, "entropy": 2.1, "cpu": 4.5, "mem": 42},
    ("syn", "medium"): {"rate": 87, "latency": 2466, "entropy": 1.4, "cpu": 7.0, "mem": 48},
    ("syn", "high"):   {"rate": 96, "latency": 1642, "entropy": 0.6, "cpu": 9.5, "mem": 55},
    ("udp", "low"):    {"rate": 78, "latency": 3027, "entropy": 2.0, "cpu": 4.2, "mem": 41},
    ("udp", "medium"): {"rate": 85, "latency": 2375, "entropy": 1.3, "cpu": 6.8, "mem": 47},
    ("udp", "high"):   {"rate": 94, "latency": 1448, "entropy": 0.5, "cpu": 9.0, "mem": 53},
}
POLL_RATE_ADJUST = {1: +3, 2: 0, 5: -4}
POLL_LATENCY_ADJUST = {1: -400, 2: 0, 5: +900}

RUNS_PER_CONFIG = 5

rows = []
run_id = 1
for (attack_type, intensity), stats in BASE_STATS.items():
    for poll in (1, 2, 5):
        adj_rate = stats["rate"] + POLL_RATE_ADJUST[poll]
        adj_latency = stats["latency"] + POLL_LATENCY_ADJUST[poll]
        for _ in range(RUNS_PER_CONFIG):
            detection_rate = max(0, min(100, random.gauss(adj_rate, 3)))
            detection_latency = max(50, random.gauss(adj_latency, adj_latency * 0.25))
            avg_entropy = max(0.0, random.gauss(stats["entropy"], 0.25))
            avg_cpu = max(0.5, random.gauss(stats["cpu"], 1.0))
            avg_mem = max(20, random.gauss(stats["mem"], 3.0))
            rows.append({
                "run_id": run_id,
                "attack_type": attack_type,
                "intensity": intensity,
                "poll_interval": poll,
                "detection_rate_pct": round(detection_rate, 2),
                "detection_latency_ms": round(detection_latency, 2),
                "avg_entropy": round(avg_entropy, 3),
                "avg_cpu_pct": round(avg_cpu, 2),
                "avg_mem_mb": round(avg_mem, 2),
            })
            run_id += 1

os.makedirs(os.path.dirname(OUT_PATH), exist_ok=True)
with open(OUT_PATH, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=[
        "run_id", "attack_type", "intensity", "poll_interval",
        "detection_rate_pct", "detection_latency_ms", "avg_entropy",
        "avg_cpu_pct", "avg_mem_mb",
    ])
    w.writeheader()
    w.writerows(rows)

print(f"Wrote {len(rows)} synthetic rows to {OUT_PATH}")
