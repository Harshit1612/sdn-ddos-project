import argparse
import os
import sys
import time
import csv
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel, info

from topology.topo import DataCenterTopo

os.makedirs("results", exist_ok=True)

INTENSITY_MAP = {
    "low":    {"hping_interval": "u10000", "n_attackers": 1},
    "medium": {"hping_interval": "u1000",  "n_attackers": 2},
    "high":   {"hping_interval": None,      "n_attackers": 3},  # None -> --flood
}

BENIGN_DEST_HOSTS = ["h9", "h10", "h11", "h12"]
BENIGN_SRC_HOSTS  = ["h1", "h2", "h3", "h4", "h5", "h6"]
ATTACK_TARGET     = "h12"
ATTACK_TARGET_IP  = "10.0.0.12"
ATTACKER_HOSTS    = ["h1", "h2", "h3"]


def start_benign_traffic(net, duration):
    info("*** Starting benign iperf3 background traffic\n")
    for dst_name in BENIGN_DEST_HOSTS:
        net.get(dst_name).cmd("iperf3 -s -p 5201 -D")
    time.sleep(1)

    pairs = list(zip(BENIGN_SRC_HOSTS, BENIGN_DEST_HOSTS * 2))
    for src_name, dst_name in pairs:
        src = net.get(src_name)
        dst_ip = net.get(dst_name).IP()
        src.cmd(
            "iperf3 -c {} -p 5201 -t {} -b 10M > /tmp/{}_iperf.log 2>&1 &".format(
                dst_ip, duration, src_name
            )
        )
    info("*** Benign traffic started ({} flows)\n".format(len(pairs)))


def stop_benign_traffic(net):
    for src_name in BENIGN_SRC_HOSTS:
        net.get(src_name).cmd("pkill iperf3")
    for dst_name in BENIGN_DEST_HOSTS:
        net.get(dst_name).cmd("pkill iperf3")


def start_attack(net, attack_type, intensity, duration):
    cfg = INTENSITY_MAP[intensity]
    n_attackers = cfg["n_attackers"]
    attackers = ATTACKER_HOSTS[:n_attackers]

    info("*** Starting {} flood ({} intensity) from {} attacker(s) -> {}\n".format(
        attack_type.upper(), intensity, len(attackers), ATTACK_TARGET_IP))

    flag = "--udp" if attack_type == "udp" else "--syn"

    for name in attackers:
        h = net.get(name)
        if cfg["hping_interval"] is None:
            rate_flag = "--flood"
        else:
            rate_flag = "-i {}".format(cfg["hping_interval"])
        cmd = "timeout {} hping3 {} {} -p 80 {} > /tmp/{}_attack.log 2>&1 &".format(
            duration, flag, rate_flag, ATTACK_TARGET_IP, name
        )
        h.cmd(cmd)

    return attackers


def stop_attack(net, attackers):
    for name in attackers:
        net.get(name).cmd("pkill hping3")


def record_attack_window(attack_type, intensity, start_ts, end_ts):
    path = "results/attack_windows.csv"
    write_header = not os.path.exists(path)
    with open(path, "a", newline="") as f:
        w = csv.writer(f)
        if write_header:
            w.writerow(["attack_type", "intensity", "start_ts", "end_ts"])
        w.writerow([attack_type, intensity, start_ts, end_ts])


def main():
    parser = argparse.ArgumentParser(description="Traffic generator for SDN DDoS testbed")
    parser.add_argument("--controller", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=6653)
    parser.add_argument("--mode", choices=["benign", "attack", "both"], default="both")
    parser.add_argument("--type", choices=["syn", "udp"], default="syn")
    parser.add_argument("--intensity", choices=["low", "medium", "high"], default="medium")
    parser.add_argument("--duration", type=int, default=60, help="attack duration in seconds")
    parser.add_argument("--baseline", type=int, default=10, help="benign-only warmup seconds before attack")
    args = parser.parse_args()

    setLogLevel("info")
    topo = DataCenterTopo()
    net = Mininet(topo=topo, switch=OVSSwitch, controller=None,
                   autoSetMacs=True, waitConnected=True, link=TCLink)
    net.addController("c0", controller=RemoteController,
                       ip=args.controller, port=args.port)
    net.start()
    info("*** Waiting for switches to settle\n")
    time.sleep(3)
    net.pingAll()

    try:
        if args.mode in ("benign", "both"):
            total_benign_duration = args.baseline + args.duration if args.mode == "both" else args.duration
            start_benign_traffic(net, total_benign_duration)

        if args.mode == "both":
            info("*** Baseline warmup: {}s of benign-only traffic\n".format(args.baseline))
            time.sleep(args.baseline)

        if args.mode in ("attack", "both"):
            attack_start = datetime.now().isoformat()
            attackers = start_attack(net, args.type, args.intensity, args.duration)
            info("*** Attack running for {}s\n".format(args.duration))
            time.sleep(args.duration)
            stop_attack(net, attackers)
            attack_end = datetime.now().isoformat()
            record_attack_window(args.type, args.intensity, attack_start, attack_end)
            info("*** Attack window recorded: {} -> {}\n".format(attack_start, attack_end))

        if args.mode in ("benign", "both"):
            info("*** Letting benign flows finish naturally\n")
            time.sleep(3)
            stop_benign_traffic(net)

    finally:
        info("*** Traffic generation complete, tearing down network\n")
        net.stop()


if __name__ == "__main__":
    main()
