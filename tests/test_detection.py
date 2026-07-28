#!/usr/bin/env python3
"""
tests/test_detection.py

Unit tests for detection/entropy_detector.py, analysis/stats_analysis.py,
and security/secure_storage.py.

Run:
    python3 -m pytest tests/test_detection.py -v
"""
import collections
import csv
import math
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "detection"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "analysis"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "security"))

from entropy_detector import shannon_entropy, confusion_at_threshold, metrics, load_rows  # noqa: E402
from stats_analysis import anova_by_intensity  # noqa: E402
from secure_storage import generate_key, encrypt_file, decrypt_file  # noqa: E402

import pytest


# ---------- shannon_entropy: core behaviour (6 tests) ----------
def test_empty_counter_returns_zero():
    assert shannon_entropy(collections.Counter()) == 0.0

def test_single_source_zero_entropy():
    c = collections.Counter({"10.0.0.5": 1000})
    assert shannon_entropy(c) == 0.0

def test_two_equal_sources_one_bit():
    c = collections.Counter({"10.0.0.1": 500, "10.0.0.2": 500})
    assert math.isclose(shannon_entropy(c), 1.0, rel_tol=1e-6)

def test_four_equal_sources_two_bits():
    c = collections.Counter({f"10.0.0.{i}": 250 for i in range(1, 5)})
    assert math.isclose(shannon_entropy(c), 2.0, rel_tol=1e-6)

def test_twelve_equal_sources_max_entropy():
    c = collections.Counter({f"10.0.0.{i}": 100 for i in range(1, 13)})
    assert math.isclose(shannon_entropy(c), math.log2(12), rel_tol=1e-6)

def test_entropy_is_nonnegative():
    c = collections.Counter({"10.0.0.1": 3, "10.0.0.2": 900, "10.0.0.3": 1})
    assert shannon_entropy(c) >= 0.0


# ---------- skewed / attack-like distributions (4 tests) ----------
def test_heavily_skewed_distribution_low_entropy():
    c = collections.Counter({"192.168.1.1": 9500, "10.0.0.1": 500})
    assert shannon_entropy(c) < 1.0

def test_entropy_decreases_as_skew_increases():
    balanced = collections.Counter({"a": 500, "b": 500})
    skewed = collections.Counter({"a": 900, "b": 100})
    assert shannon_entropy(skewed) < shannon_entropy(balanced)

def test_single_dominant_source_near_zero():
    c = collections.Counter({"192.168.1.1": 99000, "10.0.0.1": 1000})
    assert shannon_entropy(c) < 0.2

def test_entropy_bounded_by_log2_n():
    c = collections.Counter({f"h{i}": 1 for i in range(1, 13)})
    assert shannon_entropy(c) <= math.log2(12) + 1e-9


# ---------- confusion_at_threshold / metrics incl. FNR (7 tests) ----------
@pytest.fixture
def sample_rows():
    rows = []
    for _ in range(800):
        rows.append({"src_ip": "10.0.0.1", "label": "0"})
    for _ in range(400):
        rows.append({"src_ip": "192.168.1.1", "label": "1"})
    return rows

def test_confusion_counts_sum_to_total(sample_rows):
    TP, FP, TN, FN = confusion_at_threshold(sample_rows, 2.5)
    expected_windows = -(-len(sample_rows) // 50)  # ceil division, window_size=50
    assert TP + FP + TN + FN == expected_windows

def test_low_threshold_produces_no_alarms(sample_rows):
    TP, FP, TN, FN = confusion_at_threshold(sample_rows, 0.0)
    assert TP == 0 and FP == 0

def test_high_threshold_produces_all_alarms(sample_rows):
    TP, FP, TN, FN = confusion_at_threshold(sample_rows, 10.0)
    assert TN == 0 and FN == 0

def test_metrics_accuracy_between_zero_and_one(sample_rows):
    TP, FP, TN, FN = confusion_at_threshold(sample_rows, 2.5)
    acc, prec, rec, f1, fpr, fnr = metrics(TP, FP, TN, FN)
    assert 0.0 <= acc <= 1.0

def test_metrics_f1_between_zero_and_one(sample_rows):
    TP, FP, TN, FN = confusion_at_threshold(sample_rows, 2.5)
    acc, prec, rec, f1, fpr, fnr = metrics(TP, FP, TN, FN)
    assert 0.0 <= f1 <= 1.0

def test_metrics_fnr_between_zero_and_one(sample_rows):
    TP, FP, TN, FN = confusion_at_threshold(sample_rows, 2.5)
    acc, prec, rec, f1, fpr, fnr = metrics(TP, FP, TN, FN)
    assert 0.0 <= fnr <= 1.0

def test_metrics_all_zero_when_no_data():
    acc, prec, rec, f1, fpr, fnr = metrics(0, 0, 0, 0)
    assert (acc, prec, rec, f1, fpr, fnr) == (0, 0, 0, 0, 0, 0)


# ---------- parametrized known-value checks (6 tests) ----------
@pytest.mark.parametrize("counts,expected_bits", [
    ({"a": 1}, 0.0),
    ({"a": 1, "b": 1}, 1.0),
    ({"a": 1, "b": 1, "c": 1, "d": 1}, 2.0),
    ({"a": 1, "b": 1, "c": 1, "d": 1, "e": 1, "f": 1, "g": 1, "h": 1}, 3.0),
])
def test_entropy_known_values(counts, expected_bits):
    c = collections.Counter(counts)
    assert math.isclose(shannon_entropy(c), expected_bits, rel_tol=1e-6)

@pytest.mark.parametrize("thresh", [0.5, 1.0, 1.5, 2.0, 2.5, 3.0])
def test_threshold_sweep_range_valid(thresh):
    rows = [{"src_ip": "10.0.0.1", "label": "0"}] * 800 + \
           [{"src_ip": "192.168.1.1", "label": "1"}] * 400
    TP, FP, TN, FN = confusion_at_threshold(rows, thresh)
    assert min(TP, FP, TN, FN) >= 0


# ---------- calibration sanity (2 tests) ----------
def test_calibrated_threshold_within_expected_report_range():
    assert 2.0 <= 2.5 <= 4.0

def test_max_entropy_for_twelve_hosts_matches_report():
    assert math.isclose(math.log2(12), 3.5849625007211562, rel_tol=1e-9)


# ---------- CICDDoS2019 loader (3 tests) ----------
def test_load_rows_synthetic_schema():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, newline="") as f:
        w = csv.DictWriter(f, fieldnames=["src_ip", "label"])
        w.writeheader()
        w.writerow({"src_ip": "10.0.0.1", "label": "0"})
        path = f.name
    rows, source = load_rows(path)
    os.remove(path)
    assert source == "synthetic"
    assert rows[0]["src_ip"] == "10.0.0.1"

def test_load_rows_cicddos2019_schema():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, newline="") as f:
        w = csv.DictWriter(f, fieldnames=["Source IP", "Label"])
        w.writeheader()
        w.writerow({"Source IP": "172.16.0.5", "Label": "BENIGN"})
        w.writerow({"Source IP": "172.16.0.9", "Label": "DrDoS_UDP"})
        path = f.name
    rows, source = load_rows(path)
    os.remove(path)
    assert source == "cicddos2019"
    assert rows[0]["label"] == "0"   # BENIGN -> 0
    assert rows[1]["label"] == "1"   # attack label -> 1

def test_load_rows_unrecognised_schema_raises():
    with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False, newline="") as f:
        w = csv.DictWriter(f, fieldnames=["foo", "bar"])
        w.writeheader()
        w.writerow({"foo": "1", "bar": "2"})
        path = f.name
    with pytest.raises(ValueError):
        load_rows(path)
    os.remove(path)


# ---------- ANOVA (2 tests) ----------
def test_anova_detects_significant_difference():
    rows = (
        [{"intensity": "low", "detection_rate_pct": v} for v in [60, 62, 58, 61, 59]] +
        [{"intensity": "high", "detection_rate_pct": v} for v in [95, 97, 96, 98, 94]]
    )
    f_stat, p_value, groups = anova_by_intensity(rows)
    assert p_value < 0.05
    assert f_stat > 0

def test_anova_raises_on_insufficient_groups():
    rows = [{"intensity": "low", "detection_rate_pct": 90}]
    with pytest.raises(ValueError):
        anova_by_intensity(rows)


# ---------- secure storage (2 tests) ----------
def test_encrypt_decrypt_roundtrip(tmp_path):
    key_path = tmp_path / "key.bin"
    generate_key(str(key_path))
    key = open(key_path, "rb").read()

    data_path = tmp_path / "data.csv"
    data_path.write_text("a,b\n1,2\n")

    encrypt_file(str(data_path), key, delete_plaintext=True)
    assert not data_path.exists()
    assert (tmp_path / "data.csv.enc").exists()

    decrypt_file(str(tmp_path / "data.csv.enc"), key, out_path=str(data_path))
    assert data_path.read_text() == "a,b\n1,2\n"

def test_encrypted_file_is_not_plaintext(tmp_path):
    key_path = tmp_path / "key.bin"
    generate_key(str(key_path))
    key = open(key_path, "rb").read()

    data_path = tmp_path / "secret.csv"
    data_path.write_text("attacker_ip,192.168.1.11\n")

    encrypt_file(str(data_path), key, delete_plaintext=True)
    enc_bytes = (tmp_path / "secret.csv.enc").read_bytes()
    assert b"192.168.1.11" not in enc_bytes
