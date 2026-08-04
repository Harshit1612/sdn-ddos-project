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
 
        # --- mac <-> ip learning (needed because forwarding flows only
        # match on L2 fields, so flow stats alone can't tell us the IP) ---
        self.mac_to_ip = {}
        self._mac_ip_lock = threading.Lock()
 
        # --- per (dpid, mac) last-seen cumulative packet_count, so we can
        # compute a DELTA each poll instead of an ever-growing total ---
        self.last_packet_count = {}
 
        # --- detection latency tracking ---
        self.entropy_below_thresh_since = None
 
        # --- per-interval aggregation across ALL switches, so one poll
        # interval produces exactly one entropy sample (not one per switch) ---
        self._accum_counter = collections.Counter()
        self._accum_lock = threading.Lock()
 
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
 
        # learn mac -> ip whenever we see an IP packet, so flow-stats
        # (which only carry L2 match fields) can be attributed to an IP
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt:
            with self._mac_ip_lock:
                self.mac_to_ip[eth.src] = ip_pkt.src
 
        dst, src = eth.dst, eth.src
        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port
 
        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]
 
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(datapath, 1, match, actions, idle_timeout=120)
 
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
 
    # ---------------- entropy monitoring loop (flow-stats based) ----------------
    def _monitor(self):
        while True:
            for dp in list(self.datapaths.values()):
                self._request_stats(dp)
            hub.sleep(POLL_INTERVAL)
            self._process_interval()
 
    def _request_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)
 
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        """Collect this switch's delta packet counts into the shared
        per-interval accumulator. Does NOT compute entropy itself --
        that happens once per interval in _process_interval(), after
        all switches have reported in, so one interval == one data point."""
        dpid = ev.msg.datapath.id
 
        with self._mac_ip_lock:
            mac_to_ip_snapshot = dict(self.mac_to_ip)
 
        local_delta = collections.Counter()
        for stat in ev.msg.body:
            eth_src = stat.match.get("eth_src")
            if not eth_src:
                continue  # e.g. the table-miss rule, no eth_src match
            src_ip = mac_to_ip_snapshot.get(eth_src)
            if not src_ip:
                continue  # haven't learned this mac's ip yet
 
            key = (dpid, eth_src)
            prev_count = self.last_packet_count.get(key, stat.packet_count)
            delta = max(0, stat.packet_count - prev_count)
            self.last_packet_count[key] = stat.packet_count
 
            if delta > 0:
                local_delta[src_ip] += delta
 
        if local_delta:
            with self._accum_lock:
                self._accum_counter.update(local_delta)
 
    def _process_interval(self):
        """Runs once per POLL_INTERVAL, after stats from ALL switches for
        this cycle have been folded into self._accum_counter. This gives
        one entropy sample per interval instead of one per switch."""
        with self._accum_lock:
            src_ip_counter = self._accum_counter
            self._accum_counter = collections.Counter()
 
        if not src_ip_counter:
            return  # no new traffic seen this window on any switch
 
        h = self._shannon_entropy(src_ip_counter)
        detection_flag = 1 if h < ENTROPY_THRESH else 0
        cpu_pct, mem_mb = self._current_resource_snapshot()
        latency_ms = None
        now = time.time()
 
        if detection_flag:
            if self.entropy_below_thresh_since is None:
                self.entropy_below_thresh_since = now
            attacker_ip = src_ip_counter.most_common(1)[0][0]
            self.logger.info(
                "ALERT DDoS detected | entropy=%.3f | suspected_src=%s", h, attacker_ip
            )
            self._install_mitigation_all_switches(attacker_ip)
            latency_ms = round((time.time() - self.entropy_below_thresh_since) * 1000, 2)
        else:
            self.entropy_below_thresh_since = None
 
        self._log_metrics(h, detection_flag, cpu_pct, mem_mb, len(src_ip_counter), latency_ms)
 
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
    def _install_mitigation_all_switches(self, attacker_ip):
        if attacker_ip in self.blocked_ips:
            return
        for dp in list(self.datapaths.values()):
            if MITIGATION_MODE == "rate_limit":
                self._install_rate_limit_rule(dp, attacker_ip)
            else:
                self._install_drop_rule(dp, attacker_ip)
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
 
