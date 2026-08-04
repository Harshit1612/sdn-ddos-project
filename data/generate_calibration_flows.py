#!/usr/bin/env python3
"""
data/generate_calibration_flows.py

Generates a synthetic calibration_flows.csv for calibrating
ENTROPY_THRESH in controller/ddos_controller.py, matching the schema
already used elsewhere in this project:

    src_ip, dst_ip, proto, dst_port, packets, bytes, duration, label

This REPLACES the original (lost) generator. The key fix vs. the old
file: attack rows now come from a SMALL POOL of attacker IPs repeated
many times each (mimicking a real botnet / flood, where the same
handful of sources hammer the target), instead of a fresh random IP
per row. A fresh random IP per attack row makes attack traffic look
MORE diverse than normal traffic, which is the opposite of what a real
DDoS looks like and makes entropy-based detection impossible to
calibrate correctly.

Layout produced (already ordered, no need for reorder_calibration.py):
    baseline traffic (label=0) -> attack burst (label=1) -> recovery (label=0)

Run:
    python3 data/generate_calibration_flows.py --output data/calibration_flows.csv
    python3 data/generate_calibration_flows.py --output data/calibration_flows.csv \\
        --n-baseline 480 --n-attack 400 --n-recovery 320 --n-attackers 3
"""
import argparse
import csv
import random


NORMAL_HOST_IPS = [f"10.0.0.{i}" for i in range(1, 13)]  # 12 normal hosts, mirrors old data
TARGET_IP = "10.0.0.12"
NORMAL_PORTS = [80, 443, 22, 5201, 5202]
PROTOS = ["6", "17"]  # TCP, UDP


def random_attacker_pool(n_attackers):
    """Small pool of attacker IPs, like a real (small) botnet / a handful
    of spoofed sources -- NOT a fresh IP per packet."""
    pool = []
    for _ in range(n_attackers):
        pool.append(f"192.168.{random.randint(2, 6)}.{random.randint(2, 254)}")
    return pool


def make_benign_row():
    src = random.choice(NORMAL_HOST_IPS)
    dst = random.choice([ip for ip in NORMAL_HOST_IPS if ip != src])
    proto = random.choice(PROTOS)
    port = random.choice(NORMAL_PORTS)
    packets = random.randint(100, 900)
    byte_count = packets * random.randint(40, 120)
    duration = round(random.uniform(0.3, 12.0), 3)
    return {
        "src_ip": src, "dst_ip": dst, "proto": proto, "dst_port": port,
        "packets": packets, "bytes": byte_count, "duration": duration,
        "label": "0",
    }


def make_attack_row(attacker_pool):
    # each attack row picks ONE of the small attacker pool -- this is what
    # makes the attack-window source-IP distribution low entropy (few
    # distinct IPs dominating), matching a real SYN/UDP flood.
    src = random.choice(attacker_pool)
    packets = random.randint(5000, 35000)   # flood-scale packet counts
    byte_count = packets * random.randint(60, 320)
    duration = round(random.uniform(0.3, 1.2), 3)  # short bursts, flood-like
    proto = "6"  # SYN flood == TCP
    return {
        "src_ip": src, "dst_ip": TARGET_IP, "proto": proto, "dst_port": 80,
        "packets": packets, "bytes": byte_count, "duration": duration,
        "label": "1",
    }


def main():
    parser = argparse.ArgumentParser(description="Generate a realistic calibration_flows.csv")
    parser.add_argument("--output", required=True, help="output CSV path")
    parser.add_argument("--n-baseline", type=int, default=480, help="rows of pre-attack baseline traffic")
    parser.add_argument("--n-attack", type=int, default=400, help="rows of attack traffic")
    parser.add_argument("--n-recovery", type=int, default=320, help="rows of post-attack recovery traffic")
    parser.add_argument("--n-attackers", type=int, default=3,
                         help="size of the attacker IP pool (small = more realistic flood)")
    parser.add_argument("--seed", type=int, default=42, help="random seed for reproducibility")
    args = parser.parse_args()

    random.seed(args.seed)
    attacker_pool = random_attacker_pool(args.n_attackers)
    print(f"Attacker pool ({args.n_attackers} IPs): {attacker_pool}")

    rows = []
    rows += [make_benign_row() for _ in range(args.n_baseline)]
    rows += [make_attack_row(attacker_pool) for _ in range(args.n_attack)]
    rows += [make_benign_row() for _ in range(args.n_recovery)]

    fieldnames = ["src_ip", "dst_ip", "proto", "dst_port", "packets", "bytes", "duration", "label"]
    with open(args.output, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} rows to {args.output}")
    print(f"Structure: {args.n_baseline} baseline (label=0) -> "
          f"{args.n_attack} attack burst (label=1, {args.n_attackers} attacker IPs) -> "
          f"{args.n_recovery} recovery (label=0)")
    print("\nNext steps:")
    print(f"  python3 detection/entropy_detector.py --input {args.output} --sweep")
    print(f"  python3 detection/plot_confusion_matrix.py --input {args.output} --threshold 2.5")


if __name__ == "__main__":
    main()
