import sys, os, math
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from detection.entropy_detector import shannon_entropy, EntropyDetector, FlowRecord


class TestShannonEntropy:
    def test_empty(self):
        assert shannon_entropy({}) == 0.0

    def test_single_source(self):
        assert shannon_entropy({"10.0.0.1": 100}) == 0.0

    def test_uniform_two(self):
        h = shannon_entropy({"10.0.0.1": 50, "10.0.0.2": 50})
        assert abs(h - 1.0) < 1e-9

    def test_uniform_four(self):
        h = shannon_entropy({"a": 25, "b": 25, "c": 25, "d": 25})
        assert abs(h - 2.0) < 1e-9

    def test_skewed_distribution_lower_than_uniform(self):
        uniform = shannon_entropy({"a": 25, "b": 25, "c": 25, "d": 25})
        skewed = shannon_entropy({"a": 97, "b": 1, "c": 1, "d": 1})
        assert skewed < uniform

    def test_zero_count_ignored(self):
        h1 = shannon_entropy({"a": 50, "b": 50})
        h2 = shannon_entropy({"a": 50, "b": 50, "c": 0})
        assert abs(h1 - h2) < 1e-9

    def test_entropy_never_negative(self):
        h = shannon_entropy({"a": 1, "b": 2, "c": 3, "d": 4, "e": 100})
        assert h >= 0.0

    def test_entropy_bounded_by_log2n(self):
        counter = {str(i): 10 for i in range(8)}
        h = shannon_entropy(counter)
        assert h <= math.log2(8) + 1e-9


class TestEntropyDetector:
    def make_flows(self, src_ip_packets, dst_ip="10.0.0.12", proto=6, dst_port=80, duration=1.0, label=0):
        return [
            FlowRecord(src_ip=ip, dst_ip=dst_ip, proto=proto, dst_port=dst_port,
                       packets=pkts, byte_cnt=pkts * 60, duration=duration, label=label)
            for ip, pkts in src_ip_packets.items()
        ]

    def test_benign_traffic_no_alarm(self):
        det = EntropyDetector(entropy_thresh=2.5, pkt_thresh=5000, min_flows=5)
        flows = self.make_flows({f"10.0.0.{i}": 50 for i in range(1, 9)})
        result = det.analyse(flows)
        assert result.alarm is False
        assert result.entropy > 2.5

    def test_attack_traffic_triggers_entropy_alarm(self):
        det = EntropyDetector(entropy_thresh=2.5, pkt_thresh=999999, min_flows=5)
        flows = self.make_flows({
            "192.168.1.1": 9000, "192.168.1.2": 10, "192.168.1.3": 10,
            "192.168.1.4": 10, "192.168.1.5": 10
        })
        result = det.analyse(flows)
        assert result.alarm is True
        assert "entropy" in result.reason

    def test_too_few_flows_suppresses_entropy_alarm(self):
        det = EntropyDetector(entropy_thresh=2.5, pkt_thresh=999999, min_flows=5)
        flows = self.make_flows({"192.168.1.1": 9000})
        result = det.analyse(flows)
        assert result.alarm is False

    def test_rate_alarm_triggers_on_high_packet_rate(self):
        det = EntropyDetector(entropy_thresh=0.0, pkt_thresh=100, poll_interval=1.0, min_flows=1)
        flows = self.make_flows({"10.0.0.1": 5000})
        result = det.analyse(flows)
        assert result.alarm is True
        assert "rate_alarm" in result.reason

    def test_no_alarm_below_rate_threshold(self):
        det = EntropyDetector(entropy_thresh=0.0, pkt_thresh=100000, poll_interval=1.0, min_flows=1)
        flows = self.make_flows({"10.0.0.1": 500})
        result = det.analyse(flows)
        assert result.alarm is False

    def test_window_id_increments(self):
        det = EntropyDetector()
        flows = self.make_flows({"10.0.0.1": 50, "10.0.0.2": 50})
        r1 = det.analyse(flows)
        r2 = det.analyse(flows)
        assert r2.window_id == r1.window_id + 1

    def test_reset_clears_state(self):
        det = EntropyDetector()
        flows = self.make_flows({"10.0.0.1": 50})
        det.analyse(flows)
        det.reset()
        assert det._win_id == 0
        assert det._prev == {}

    def test_n_flows_matches_input(self):
        det = EntropyDetector(min_flows=1)
        flows = self.make_flows({f"10.0.0.{i}": 10 for i in range(1, 6)})
        result = det.analyse(flows)
        assert result.n_flows == 5

    def test_top_srcs_sorted_descending(self):
        det = EntropyDetector(min_flows=1)
        flows = self.make_flows({"10.0.0.1": 10, "10.0.0.2": 100, "10.0.0.3": 50})
        result = det.analyse(flows)
        packet_counts = [c for _, c in result.top_srcs]
        assert packet_counts == sorted(packet_counts, reverse=True)

    def test_latency_is_measured(self):
        det = EntropyDetector(min_flows=1)
        flows = self.make_flows({"10.0.0.1": 50, "10.0.0.2": 50})
        result = det.analyse(flows)
        assert result.latency_ms >= 0.0

    def test_empty_flow_list(self):
        det = EntropyDetector(min_flows=1)
        result = det.analyse([])
        assert result.entropy == 0.0
        assert result.n_flows == 0

    def test_custom_thresholds_applied(self):
        det = EntropyDetector(entropy_thresh=1.0, pkt_thresh=999999, min_flows=2)
        flows = self.make_flows({"10.0.0.1": 50, "10.0.0.2": 50})
        result = det.analyse(flows)
        assert result.alarm is False

    def test_rate_alarm_identifies_correct_source(self):
        det = EntropyDetector(entropy_thresh=0.0, pkt_thresh=100, poll_interval=1.0, min_flows=1)
        flows = self.make_flows({"10.0.0.1": 5000, "10.0.0.2": 50})
        result = det.analyse(flows)
        assert "10.0.0.1" in result.reason
        assert "10.0.0.2" not in result.reason.replace("10.0.0.1", "")


class TestLoadFlowsCsv:
    def test_load_flows_from_csv(self, tmp_path):
        from detection.entropy_detector import load_flows_csv
        csv_path = tmp_path / "flows.csv"
        csv_path.write_text(
            "src_ip,dst_ip,proto,dst_port,packets,bytes,duration,label\n"
            "10.0.0.1,10.0.0.12,6,80,100,6000,1.0,0\n"
            "192.168.1.1,10.0.0.12,6,80,9000,540000,0.5,1\n"
        )
        flows = load_flows_csv(str(csv_path))
        assert len(flows) == 2
        assert flows[0].src_ip == "10.0.0.1"
        assert flows[1].label == 1
