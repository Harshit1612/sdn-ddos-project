#!/usr/bin/env python3
"""
controller/ddos_controller.py

Ryu OpenFlow 1.3 controller. Responsibilities:
  1. L2 learning-switch forwarding (packet_in -> learn MAC -> flow_mod)
  2. Every POLL_INTERVAL seconds: computes Shannon entropy of source IPs
     seen via packet_in events since the last window, and logs a metrics
     row (entropy, detection_flag, cpu_pct, mem_mb, n_flows,
     detection_latency_ms)
  3. Controller CPU/memory sampled via psutil every 500ms in a background
     thread.
  4. Detection latency: measured as the time from the FIRST polling window
     in which entropy crosses below ENTROPY_THRESH to the moment the
     mitigation flow-mod is actually installed.
  5. Mitigation supports two modes: MITIGATION_MODE = "drop" installs a DROP
     rule; MITIGATION_MODE = "rate_limit" installs an OpenFlow 1.3 meter.

NOTE (fix): source-IP entropy is computed from packet_in events, not from
flow-table stats matched on ipv4_src. Normal L2 forwarding flows installed
by this controller only match on eth_dst/eth_src/in_port -- they never have
an ipv4_src field -- so relying on flow stats meant entropy was never
computed and no metrics rows were ever written. Counting source IPs
directly off packet_in fixes this.

Run:
    ryu-manager controller/ddos_controller.py
"""
import csv
import math
import os
import time
import threading
import collections
from datetime import datetime

import psutil
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4
from ryu.lib import hub

RESULTS_DIR = "/home/harshit/sdn_ddos_project/results/"
POLL_INTERVAL = 2
ENTROPY_THRESH = 2.5
DROP_IDLE_TIMEOUT = 60
RESOURCE_SAMPLE_INTERVAL = 0.5
MITIGATION_MODE = "drop"
RATE_LIMIT_KBPS = 100


class DDoSController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DDoSController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        os.makedirs(RESULTS_DIR, exist_ok=True)
        self.metrics_file = os.path.join(
            RESULTS_DIR, f"metrics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        )
        self._init_metrics_file()
        self.blocked_ips = {}
        self.next_meter_id = 1
        self.meter_ids = {}

        # --- resource monitoring state (psutil, 500ms) ---
        self.proc = psutil.Process(os.getpid())
        self.cpu_samples = collections.deque(maxlen=20)
        self.mem_samples = collections.deque(maxlen=20)
        self._resource_lock = threading.Lock()

        # --- source-IP tracking for entropy (fix: from packet_in, not flow stats) ---
        self.src_ip_window = collections.Counter()
        self._src_ip_lock = threading.Lock()

        # --- detection latency tracking ---
        self.entropy_below_thresh_since = None

        self.monitor_thread = hub.spawn(self._monitor)
        self.resource_thread = hub.spawn(self._resource_monitor)

    def _init_metrics_file(self):
        with open(self.metrics_file, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow([
                "timestamp", "entropy", "detection_flag", "cpu_pct", "mem_mb",
                "n_flows", "detection_latency_ms", "mitigation_mode",
            ])

    # ---------------- L2 learning switch ----------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        self.datapaths[datapath.id] = datapath
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, idle_timeout=0,
                 hard_timeout=0, meter_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if meter_id is not None:
            inst.append(parser.OFPInstructionMeter(meter_id, ofproto.OFPIT_METER))
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=priority, match=match, instructions=inst,
            idle_timeout=idle_timeout, hard_timeout=hard_timeout,
        )
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        # --- fix: count source IPs here, since this is the only place we
        # reliably see every packet's IP header, regardless of what match
        # fields later get installed in the flow table ---
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            with self._src_ip_lock:
                self.src_ip_window[ip_pkt.src] += 1

        dst, src = eth.dst, eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(datapath, 1, match, actions, idle_timeout=30)

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data,
        )
        datapath.send_msg(out)

    # ---------------- resource monitoring (psutil, 500ms) ----------------
    def _resource_monitor(self):
        self.proc.cpu_percent(interval=None)
        while True:
            hub.sleep(RESOURCE_SAMPLE_INTERVAL)
            cpu = self.proc.cpu_percent(interval=None)
            mem_mb = self.proc.memory_info().rss / (1024 * 1024)
            with self._resource_lock:
                self.cpu_samples.append(cpu)
                self.mem_samples.append(mem_mb)

    def _current_resource_snapshot(self):
        with self._resource_lock:
            cpu = sum(self.cpu_samples) / len(self.cpu_samples) if self.cpu_samples else 0.0
            mem = sum(self.mem_samples) / len(self.mem_samples) if self.mem_samples else 0.0
        return round(cpu, 2), round(mem, 2)

    # ---------------- entropy monitoring loop (fix: packet_in based) ----------------
    def _monitor(self):
        while True:
            hub.sleep(POLL_INTERVAL)
            self._check_entropy()

    def _check_entropy(self):
        with self._src_ip_lock:
            counter_snapshot = self.src_ip_window.copy()
            self.src_ip_window.clear()

        if not counter_snapshot:
            # no traffic seen this window -- nothing to log yet
            return

        h = self._shannon_entropy(counter_snapshot)
        detection_flag = 1 if h < ENTROPY_THRESH else 0
        cpu_pct, mem_mb = self._current_resource_snapshot()
        latency_ms = None
        now = time.time()

        if detection_flag:
            if self.entropy_below_thresh_since is None:
                self.entropy_below_thresh_since = now
            attacker_ip = counter_snapshot.most_common(1)[0][0]
            self.logger.info(
                "ALERT DDoS detected | entropy=%.3f | suspected_src=%s", h, attacker_ip
            )
            if self.datapaths:
                dp = next(iter(self.datapaths.values()))
                self._install_mitigation(dp, attacker_ip)
                latency_ms = round((time.time() - self.entropy_below_thresh_since) * 1000, 2)
        else:
            self.entropy_below_thresh_since = None

        self._log_metrics(h, detection_flag, cpu_pct, mem_mb, len(counter_snapshot), latency_ms)

    @staticmethod
    def _shannon_entropy(counter):
        total = sum(counter.values())
        if not total:
            return 0.0
        return -sum((c / total) * math.log2(c / total) for c in counter.values() if c)

    def _log_metrics(self, entropy, detection_flag, cpu_pct, mem_mb, n_flows, latency_ms):
        with open(self.metrics_file, "a", newline="") as f:
            w = csv.writer(f)
            w.writerow([
                datetime.now().isoformat(), round(entropy, 4), detection_flag,
                cpu_pct, mem_mb, n_flows,
                latency_ms if latency_ms is not None else "",
                MITIGATION_MODE,
            ])

    # ---------------- mitigation: DROP or rate-limit (meter) ----------------
    def _install_mitigation(self, datapath, attacker_ip):
        if attacker_ip in self.blocked_ips:
            return
        if MITIGATION_MODE == "rate_limit":
            self._install_rate_limit_rule(datapath, attacker_ip)
        else:
            self._install_drop_rule(datapath, attacker_ip)
        self.blocked_ips[attacker_ip] = time.time()

    def _install_drop_rule(self, datapath, attacker_ip):
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=attacker_ip)
        actions = []
        self.add_flow(datapath, 100, match, actions, idle_timeout=DROP_IDLE_TIMEOUT)
        self.logger.info(
            "Installed DROP rule for %s (expires in %ds)", attacker_ip, DROP_IDLE_TIMEOUT
        )

    def _install_rate_limit_rule(self, datapath, attacker_ip):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        meter_id = self.next_meter_id
        self.next_meter_id += 1
        self.meter_ids[attacker_ip] = meter_id

        band = parser.OFPMeterBandDrop(rate=RATE_LIMIT_KBPS, burst_size=10)
        meter_mod = parser.OFPMeterMod(
            datapath=datapath, command=ofproto.OFPMC_ADD,
            flags=ofproto.OFPMF_KBPS, meter_id=meter_id, bands=[band],
        )
        datapath.send_msg(meter_mod)

        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=attacker_ip)
        actions = [parser.OFPActionOutput(ofproto.OFPP_NORMAL)]
        self.add_flow(datapath, 100, match, actions,
                       idle_timeout=DROP_IDLE_TIMEOUT, meter_id=meter_id)
        self.logger.info(
            "Installed RATE-LIMIT meter (%d kbps) for %s (expires in %ds)",
            RATE_LIMIT_KBPS, attacker_ip, DROP_IDLE_TIMEOUT,
        )
