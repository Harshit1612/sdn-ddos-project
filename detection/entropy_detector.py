import math, csv, argparse, collections
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

@dataclass
class FlowRecord:
    src_ip: str
    dst_ip: str
    proto: int
    dst_port: int
    packets: int
    byte_cnt: int
    duration: float
    label: int = 0

@dataclass
class WindowResult:
    window_id: int
    entropy: float
    n_flows: int
    alarm: bool
    reason: str
    top_srcs: list
    latency_ms: float = 0.0

def shannon_entropy(counter):
    total = sum(counter.values())
    if total == 0:
        return 0.0
    H = 0.0
    for c in counter.values():
        if c > 0:
            p = c / total
            H -= p * math.log2(p)
    return H

class EntropyDetector:
    def __init__(self, entropy_thresh=2.5, pkt_thresh=5000,
                 poll_interval=2.0, min_flows=5):
        self.entropy_thresh = entropy_thresh
        self.pkt_thresh = pkt_thresh
        self.poll_interval = poll_interval
        self.min_flows = min_flows
        self._prev = {}
        self._win_id = 0

    def analyse(self, flows):
        import time
        t0 = time.perf_counter()
        self._win_id += 1
        src_ctr = collections.Counter()
        for f in flows:
            src_ctr[f.src_ip] += f.packets
        entropy = shannon_entropy(src_ctr)
        n_flows = len(flows)
        rate_alarm = set()
        for f in flows:
            key = (f.src_ip, f.dst_ip, f.proto, f.dst_port)
            prev = self._prev.get(key, 0)
            rate = (f.packets - prev) / self.poll_interval
            if rate > self.pkt_thresh:
                rate_alarm.add(f.src_ip)
            self._prev[key] = f.packets
        entropy_alarm = entropy < self.entropy_thresh and n_flows >= self.min_flows
        alarm = entropy_alarm or bool(rate_alarm)
        reasons = []
        if entropy_alarm:
            reasons.append("entropy={:.3f}".format(entropy))
        if rate_alarm:
            reasons.append("rate_alarm={}".format(rate_alarm))
        reason = " | ".join(reasons) if reasons else "none"
        top_srcs = sorted(src_ctr.items(), key=lambda x: x[1], reverse=True)[:5]
        latency_ms = (time.perf_counter() - t0) * 1000
        return WindowResult(self._win_id, entropy, n_flows, alarm, reason, top_srcs, latency_ms)

    def reset(self):
        self._prev = {}
        self._win_id = 0

def load_flows_csv(path):
    records = []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            records.append(FlowRecord(
                src_ip=row["src_ip"], dst_ip=row.get("dst_ip", "0.0.0.0"),
                proto=int(row.get("proto", 0)), dst_port=int(row.get("dst_port", 0)),
                packets=int(row["packets"]), byte_cnt=int(row.get("bytes", 0)),
                duration=float(row.get("duration", 0.0)), label=int(row.get("label", 0))))
    return records

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Offline Entropy Detector")
    parser.add_argument("--input", required=True)
    parser.add_argument("--threshold", type=float, default=2.5)
    parser.add_argument("--sweep", action="store_true")
    args = parser.parse_args()

    flows = load_flows_csv(args.input)
    det = EntropyDetector(args.threshold)
    result = det.analyse(flows)
    print("Entropy :", round(result.entropy, 4))
    print("Alarm   :", result.alarm)
    print("Reason  :", result.reason)
    print("Latency : {:.3f} ms".format(result.latency_ms))

    if args.sweep:
        print("\n=== Threshold Sweep ===")
        print("{:>12} {:>10} {:>8}".format("Threshold", "Entropy", "Alarm"))
        for t in [0.5, 1.0, 1.5, 2.0, 2.5, 3.0, 3.5, 4.0]:
            d = EntropyDetector(t)
            r = d.analyse(flows)
            flag = " <- current" if t == args.threshold else ""
            print("  {:>10.1f} {:>10.4f} {:>8}{}".format(t, r.entropy, r.alarm, flag))
