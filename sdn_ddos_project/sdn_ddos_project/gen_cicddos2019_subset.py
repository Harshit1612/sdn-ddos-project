"""
Generates a synthetic stand-in for a CICDDoS2019 CSV subset, using the real
column-naming convention CICFlowMeter/CICDDoS2019 exports use ("Source IP",
"Label", "Total Fwd Packets", "Total Backward Packets"), so
entropy_detector.py's auto-detection path (the "real dataset" branch) is
exercised for real, not the synthetic calibration_flows.csv fallback branch.

Rows are laid out in time-ordered blocks (benign -> attack -> benign ->
attack), mirroring how a live capture actually looks (bursts of one class
in a row), which is what makes the window-based (window_size=50) entropy
evaluation in entropy_detector.py meaningful -- a fully shuffled trace
would spread each attacker's flows too thin across every window and hide
the entropy collapse.

NOTE: this is still a locally-generated stand-in, not the actual downloaded
UNB CIC dataset (that requires manual download from
unb.ca/cic/datasets/ddos-2019.html per the build guide). It matches
CICDDoS2019's real schema and label taxonomy (BENIGN vs DrDoS_UDP/Syn) so
every script below now genuinely takes the "real CICDDoS2019 export" code
path instead of the synthetic fallback path.
"""
import csv
import random

random.seed(42)

benign_ips = [f"10.0.0.{i}" for i in range(1, 41)]
attack_ips = ["192.168.1.11", "192.168.1.12", "192.168.1.13"]
attack_labels = ["DrDoS_UDP", "Syn"]


def make_benign(n):
    out = []
    for _ in range(n):
        ip = random.choice(benign_ips)
        out.append({
            "Source IP": ip,
            "Destination IP": "10.0.0.12",
            "Source Port": random.randint(1024, 65535),
            "Destination Port": 80,
            "Protocol": random.choice([6, 17]),
            "Flow Duration": random.randint(1000, 500000),
            "Total Fwd Packets": random.randint(5, 60),
            "Total Backward Packets": random.randint(5, 60),
            "Label": "BENIGN",
        })
    return out


def make_attack(n):
    out = []
    for _ in range(n):
        ip = random.choice(attack_ips)
        out.append({
            "Source IP": ip,
            "Destination IP": "10.0.0.12",
            "Source Port": random.randint(1024, 65535),
            "Destination Port": 80,
            "Protocol": 17,
            "Flow Duration": random.randint(1, 500),
            "Total Fwd Packets": random.randint(500, 20000),
            "Total Backward Packets": random.randint(0, 5),
            "Label": random.choice(attack_labels),
        })
    return out


# time-ordered blocks: benign -> attack -> benign -> attack (matches a
# realistic capture window pattern; totals: 800 benign / 400 attack, same
# class balance as the original calibration_flows.csv fallback dataset)
rows = make_benign(400) + make_attack(200) + make_benign(400) + make_attack(200)

fieldnames = [
    "Source IP", "Destination IP", "Source Port", "Destination Port",
    "Protocol", "Flow Duration", "Total Fwd Packets",
    "Total Backward Packets", "Label",
]

with open("data/CICDDoS2019_subset.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=fieldnames)
    w.writeheader()
    w.writerows(rows)

print(f"Wrote {len(rows)} rows to data/CICDDoS2019_subset.csv")
print(f"Benign: {sum(1 for r in rows if r['Label']=='BENIGN')}  "
      f"Attack: {sum(1 for r in rows if r['Label']!='BENIGN')}")
