#!/usr/bin/env python3
"""
scripts/run_experiment_matrix.py

FIX FOR PROBLEM 2: Figures 5 (detection latency), 6 (throughput), 11
(controller CPU/mem), and the CPU/mem panels of 13 need numbers that can
ONLY come from a live Mininet + Ryu run -- no dataset, real or synthetic,
can substitute for actually executing the controller and measuring it.
This script is the "solution" for those figures: it runs the REAL 90-run
matrix (2 attack types x 3 intensities x 3 poll intervals x 5 reps) on your
own testbed VM and logs everything needed to fill in real numbers.

WHY the controller isn't restarted 90 times: POLL_INTERVAL is a controller
start-up setting (read once from POLL_INTERVAL_S at import time), so this
script restarts the controller only 3 times (once per poll interval) and
runs all 30 attack/intensity/rep combinations for that poll interval
against the SAME running controller, logging start/end timestamps for each
run to results/run_log.csv. analysis/aggregate_live_results.py then slices
the controller's continuous metrics_*.csv stream by those timestamps to
compute real per-run latency/CPU/mem, and joins in the throughput capture.

PREREQUISITES (must run as root, on a real Mininet/Ryu VM -- this will NOT
run in a sandbox without Mininet/OVS):
  - Mininet, Open vSwitch, Ryu, hping3, iperf3 all installed
  - topology/topo.py, controller/ddos_controller.py, traffic/traffic_gen.py
    already in place per the build guide's directory layout
  - run from /home/harshit/sdn_ddos_project as root:
      sudo python3 scripts/run_experiment_matrix.py

Output:
  results/metrics_poll{1,2,5}s_<timestamp>.csv   (one continuous file per poll interval,
                                                    written by ddos_controller.py itself)
  results/run_log.csv                            (start/end timestamp per individual run)
  results/throughput_log.csv                     (iperf3 Mbps baseline/during/post per run)

Then run:
  python3 analysis/aggregate_live_results.py
to turn all of that into a real results/experiment_summary.csv, and re-run
the fig5/fig6/fig11/fig13 plotting code from the build guide unmodified.
"""
import csv
import json
import os
import subprocess
import time
from datetime import datetime

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.log import setLogLevel, info

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from topology.topo import DDoSTestbedTopo  # noqa: E402

PROJECT_DIR = "/home/harshit/sdn_ddos_project"
RESULTS_DIR = os.path.join(PROJECT_DIR, "results")
RUN_LOG_PATH = os.path.join(RESULTS_DIR, "run_log.csv")
THROUGHPUT_LOG_PATH = os.path.join(RESULTS_DIR, "throughput_log.csv")

POLL_INTERVALS = [1, 2, 5]
ATTACK_TYPES = ["syn", "udp"]
INTENSITIES = ["low", "medium", "high"]
REPS = 5
ATTACK_DURATION = 20   # seconds of actual flood per rep (kept short x 90 runs = manageable)
BASELINE_GAP = 8        # seconds of quiet baseline between reps, so entropy recovers
IPERF_PROBE_SECS = 4     # short iperf3 probe used for each throughput sample


def init_logs():
    os.makedirs(RESULTS_DIR, exist_ok=True)
    if not os.path.exists(RUN_LOG_PATH):
        with open(RUN_LOG_PATH, "w", newline="") as f:
            csv.writer(f).writerow(
                ["start_ts", "end_ts", "attack_type", "intensity", "poll_interval", "rep"]
            )
    if not os.path.exists(THROUGHPUT_LOG_PATH):
        with open(THROUGHPUT_LOG_PATH, "w", newline="") as f:
            csv.writer(f).writerow(
                ["attack_type", "intensity", "poll_interval", "rep", "phase", "mbps"]
            )


def log_run(start_ts, end_ts, attack_type, intensity, poll, rep):
    with open(RUN_LOG_PATH, "a", newline="") as f:
        csv.writer(f).writerow([start_ts, end_ts, attack_type, intensity, poll, rep])


def log_throughput(attack_type, intensity, poll, rep, phase, mbps):
    with open(THROUGHPUT_LOG_PATH, "a", newline="") as f:
        csv.writer(f).writerow([attack_type, intensity, poll, rep, phase, mbps])


def iperf_probe_mbps(net, src="h1", dst="h12", secs=IPERF_PROBE_SECS):
    """Runs a short iperf3 --json probe from src->dst and returns Mbps received."""
    h_dst = net.get(dst)
    h_src = net.get(src)
    h_dst.cmd(f"iperf3 -s -p 5301 -1 -D")   # -1 = exit after one connection
    time.sleep(0.5)
    out = h_src.cmd(f"iperf3 -c {h_dst.IP()} -p 5301 -t {secs} -J")
    try:
        data = json.loads(out)
        mbps = data["end"]["sum_received"]["bits_per_second"] / 1e6
    except Exception:
        mbps = None
    return mbps


def run_one_config(net, attack_type, intensity, poll, rep):
    tag = f"{attack_type}_{intensity}_poll{poll}_rep{rep}"
    info(f"*** [{tag}] baseline probe (pre-attack throughput)\n")
    pre_mbps = iperf_probe_mbps(net)
    log_throughput(attack_type, intensity, poll, rep, "baseline", pre_mbps)

    h_attacker = net.get("h1")
    start_ts = datetime.now().isoformat()

    if attack_type == "syn":
        info(f"*** [{tag}] launching SYN flood ({intensity}) for {ATTACK_DURATION}s\n")
        h_attacker.cmd(
            f"timeout {ATTACK_DURATION} python3 {PROJECT_DIR}/traffic/traffic_gen.py "
            f"--mode attack --type syn --intensity {intensity} --duration {ATTACK_DURATION} &"
        )
    else:
        info(f"*** [{tag}] launching UDP flood ({intensity}) for {ATTACK_DURATION}s\n")
        h_attacker.cmd(
            f"timeout {ATTACK_DURATION} python3 {PROJECT_DIR}/traffic/traffic_gen.py "
            f"--mode attack --type udp --intensity {intensity} --duration {ATTACK_DURATION} &"
        )

    # mid-attack throughput probe (measures degradation felt by legitimate hosts)
    time.sleep(ATTACK_DURATION / 2)
    mid_mbps = iperf_probe_mbps(net)
    log_throughput(attack_type, intensity, poll, rep, "during", mid_mbps)

    time.sleep(ATTACK_DURATION / 2 + 1)  # let attack finish + mitigation settle
    end_ts = datetime.now().isoformat()
    log_run(start_ts, end_ts, attack_type, intensity, poll, rep)

    info(f"*** [{tag}] post-mitigation throughput probe\n")
    post_mbps = iperf_probe_mbps(net)
    log_throughput(attack_type, intensity, poll, rep, "post", post_mbps)

    info(f"*** [{tag}] baseline recovery pause ({BASELINE_GAP}s)\n")
    time.sleep(BASELINE_GAP)


def start_controller(poll):
    env = os.environ.copy()
    env["POLL_INTERVAL_S"] = str(poll)
    env["MITIGATION_MODE"] = "drop"
    env["RUN_TAG"] = f"poll{poll}s"
    proc = subprocess.Popen(
        ["ryu-manager", os.path.join(PROJECT_DIR, "controller/ddos_controller.py")],
        env=env,
    )
    time.sleep(8)  # give Ryu + OVS time to connect
    return proc


def main():
    setLogLevel("info")
    init_logs()

    for poll in POLL_INTERVALS:
        info(f"\n=== Starting controller with POLL_INTERVAL_S={poll} ===\n")
        controller_proc = start_controller(poll)

        topo = DDoSTestbedTopo()
        net = Mininet(topo=topo, switch=OVSSwitch, link=TCLink, controller=None, autoSetMacs=False)
        net.addController("c0", controller=RemoteController, ip="127.0.0.1", port=6653)
        net.start()
        net.pingAll()

        for attack_type in ATTACK_TYPES:
            for intensity in INTENSITIES:
                for rep in range(1, REPS + 1):
                    run_one_config(net, attack_type, intensity, poll, rep)

        net.stop()
        info(f"*** Stopping controller (poll={poll})\n")
        controller_proc.terminate()
        time.sleep(3)

    info("\n*** Full 90-run matrix complete. Now run:\n"
         "    python3 analysis/aggregate_live_results.py\n")


if __name__ == "__main__":
    main()
