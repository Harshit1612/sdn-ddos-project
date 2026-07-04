from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.lib import hub
import math, csv, os, collections
from datetime import datetime
import psutil

POLL_INTERVAL  = 2
ENTROPY_THRESH = 2.5
PKT_THRESH     = 5000
MIN_FLOWS      = 5
DROP_HARD_TO   = 60

os.makedirs("logs", exist_ok=True)
os.makedirs("results", exist_ok=True)

def calc_entropy(counter):
    total = sum(counter.values())
    if total == 0:
        return 0.0
    result = 0.0
    for c in counter.values():
        if c > 0:
            p = c / total
            result -= p * math.log2(p)
    return result

class DDOSController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DDOSController, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.mac_to_port = collections.defaultdict(dict)
        self.flow_prev = collections.defaultdict(dict)
        self.blocked_ips = set()
        self._proc = psutil.Process(os.getpid())
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.metric_file = os.path.join("results", "metrics_{}.csv".format(ts))
        self.alert_file  = os.path.join("logs",    "alerts_{}.log".format(ts))
        fh = open(self.metric_file, "w", newline="")
        self.csv_writer = csv.writer(fh)
        self.csv_writer.writerow([
            "timestamp","dpid","entropy","n_flows",
            "n_blocked","detection_flag","cpu_pct","mem_mb"])
        fh.flush()
        self._fh = fh
        self.monitor_thread = hub.spawn(self._monitor_loop)
        self.logger.info("DDOSController ready | poll=%ds thresh=%.2f",
                         POLL_INTERVAL, ENTROPY_THRESH)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp   = ev.msg.datapath
        ofp  = dp.ofproto
        ofpp = dp.ofproto_parser
        match   = ofpp.OFPMatch()
        actions = [ofpp.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions)
        self.datapaths[dp.id] = dp
        self.logger.info("Switch connected dpid=%s", dp.id)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg     = ev.msg
        dp      = msg.datapath
        ofp     = dp.ofproto
        ofpp    = dp.ofproto_parser
        in_port = msg.match["in_port"]
        pkt     = packet.Packet(msg.data)
        eth     = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return
        dst  = eth.dst
        src  = eth.src
        dpid = dp.id
        self.mac_to_port[dpid][src] = in_port
        out_port = self.mac_to_port[dpid].get(dst, ofp.OFPP_FLOOD)
        actions  = [ofpp.OFPActionOutput(out_port)]
        if out_port != ofp.OFPP_FLOOD:
            match = ofpp.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(dp, 1, match, actions, idle_timeout=20, hard_timeout=60)
        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        out  = ofpp.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data)
        dp.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        dp   = ev.msg.datapath
        dpid = dp.id
        src_ctr = collections.Counter()
        current = {}
        for stat in ev.msg.body:
            m      = stat.match
            src_ip = m.get("ipv4_src")
            if src_ip is None:
                continue
            key = (src_ip,
                   m.get("ipv4_dst", "0.0.0.0"),
                   m.get("ip_proto", 0),
                   m.get("tcp_dst", m.get("udp_dst", 0)))
            current[key] = {"packets": stat.packet_count}
            src_ctr[src_ip] += stat.packet_count
        entropy = calc_entropy(src_ctr)
        n_flows = len(current)
        rate_alarm = set()
        prev = self.flow_prev.get(dpid, {})
        for key, vals in current.items():
            delta = vals["packets"] - prev.get(key, {}).get("packets", 0)
            if POLL_INTERVAL > 0 and (delta / POLL_INTERVAL) > PKT_THRESH:
                rate_alarm.add(key[0])
        self.flow_prev[dpid] = current
        detected = (entropy < ENTROPY_THRESH and n_flows >= MIN_FLOWS) or bool(rate_alarm)
        if detected:
            self.mitigate(dp, src_ctr, rate_alarm, entropy)
        cpu = self._proc.cpu_percent(interval=None)
        mem = self._proc.memory_info().rss / (1024 * 1024)
        self.csv_writer.writerow([
            datetime.now().isoformat(), dpid,
            round(entropy, 4), n_flows, len(self.blocked_ips),
            int(detected), round(cpu, 2), round(mem, 2)])
        self._fh.flush()

    def mitigate(self, dp, src_ctr, rate_ips, entropy):
        top  = {ip for ip, _ in src_ctr.most_common(5)}
        news = (top | rate_ips) - self.blocked_ips
        if not news:
            return
        self.logger.warning("ALERT DDoS entropy=%.3f blocking=%s", entropy, news)
        with open(self.alert_file, "a") as af:
            af.write("{} ALERT entropy={:.3f} blocked={}\n".format(
                datetime.now().isoformat(), entropy, news))
        ofpp = dp.ofproto_parser
        for ip in news:
            match = ofpp.OFPMatch(eth_type=0x0800, ipv4_src=ip)
            self.add_flow(dp, 100, match, [], hard_timeout=DROP_HARD_TO)
            self.blocked_ips.add(ip)
            self.logger.info("DROP src=%s", ip)

    def add_flow(self, dp, priority, match, actions,
                 idle_timeout=0, hard_timeout=0):
        ofpp  = dp.ofproto_parser
        ofp   = dp.ofproto
        instr = [ofpp.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod   = ofpp.OFPFlowMod(
            datapath=dp, priority=priority, match=match,
            instructions=instr,
            idle_timeout=idle_timeout, hard_timeout=hard_timeout)
        dp.send_msg(mod)

    def _monitor_loop(self):
        while True:
            for dp in list(self.datapaths.values()):
                ofpp = dp.ofproto_parser
                req  = ofpp.OFPFlowStatsRequest(dp)
                dp.send_msg(req)
            hub.sleep(POLL_INTERVAL)
