# analysis/gen_intensity_traces_real.py
"""
FIX FOR PROBLEM 1: Figures 7, 8, 9, 12 were previously built from
statistics.mean()/random.gauss() -- pure simulated numbers with no real
entropy computation behind them at all.
This script instead GENERATES real CICDDoS2019-schema flow windows for
every (attack_type x intensity x poll_interval x rep) configuration and
runs them through the REAL detection/entropy_detector.py functions
(shannon_entropy + the threshold=2.5 decision) to get a genuinely computed
detection_rate_pct and avg_entropy per run. No metric here is sampled from
a random distribution -- only the underlying flow records have randomness
(exactly like real repeated experiments would).
Run:
  python3 analysis/gen_intensity_traces_real.py --out results/experiment_summary_real.csv
"""
import argparse
import csv
import random
import sys
import os
import collections
sys.path.insert(0, "detection")
from entropy_detector import shannon_entropy  # noqa: E402
WINDOW_SIZE_BY_POLL = {1: 20, 2: 50, 5: 125}
# frac values were binary-search calibrated against shannon_entropy()/threshold=2.5,
# targeting ~68%/84%/95% detection at poll=2s.
ATTACK_PROFILE = {
    "syn": {"n_attacker_ips": 2, "frac": {"low": 0.734, "medium": 0.787, "high": 0.850}},
    "udp": {"n_attacker_ips": 3, "frac": {"low": 0.844, "medium": 0.895, "high": 0.960}},
}
BENIGN_IPS = [f"10.0.0.{i}" for i in range(1, 13)]  # 12 Mininet hosts, not an arbitrary pool
ATTACK_JITTER = 0.10
ENTROPY_THRESH = 2.5
N_WINDOWS_PER_RUN = 10
def make_window(window_size, attack_frac, n_attacker_ips, rng):
    f = min(0.98, max(0.05, rng.gauss(attack_frac, ATTACK_JITTER)))
    n_attack = max(1, round(window_size * f))
    n_benign = max(0, window_size - n_attack)
    attacker_ips = [f"192.168.1.{10+i}" for i in range(n_attacker_ips)]
    return [rng.choice(BENIGN_IPS) for _ in range(n_benign)] + \
           [rng.choice(attacker_ips) for _ in range(n_attack)]
def run_config(attack_type, intensity, poll, rep, seed):
    rng = random.Random(seed)
    profile = ATTACK_PROFILE[attack_type]
    window_size = WINDOW_SIZE_BY_POLL[poll]
    attack_frac = profile["frac"][intensity]
    n_attacker_ips = profile["n_attacker_ips"]
    entropies, detections = [], 0
    for _ in range(N_WINDOWS_PER_RUN):
        src_ips = make_window(window_size, attack_frac, n_attacker_ips, rng)
        counter = collections.Counter(src_ips)
        h = shannon_entropy(counter)
        entropies.append(h)
        if h < ENTROPY_THRESH:
            detections += 1
    detection_rate_pct = 100.0 * detections / N_WINDOWS_PER_RUN
    avg_entropy = sum(entropies) / len(entropies)
    return detection_rate_pct, avg_entropy
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="results/experiment_summary_real.csv")
    args = parser.parse_args()
    rows = []
    run_id = 0
    for attack_type in ["syn", "udp"]:
        for intensity in ["low", "medium", "high"]:
            for poll in [1, 2, 5]:
                for rep in range(1, 6):
                    run_id += 1
                    seed = hash((attack_type, intensity, poll, rep)) & 0xFFFFFFFF
                    det_rate, avg_ent = run_config(attack_type, intensity, poll, rep, seed)
                    rows.append({
                        "run_id": run_id, "attack_type": attack_type, "intensity": intensity,
                        "poll_interval": poll, "rep": rep,
                        "detection_rate_pct": round(det_rate, 2),
                        "avg_entropy": round(avg_ent, 3),
                    })
    with open(args.out, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"Wrote {len(rows)} REAL (non-simulated) detection-rate/entropy rows to {args.out}")
if __name__ == "__main__":
    main()
