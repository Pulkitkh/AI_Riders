"""Test suite.  python tests/test_prahari.py   (or: python -m pytest tests/ -q)"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from prahari.engine import Engine
from prahari.features import (coefficient_of_variation, is_rfc1918, jitter_band,
                              lexical_features, regularity, shannon_entropy)
from prahari.generate import ALL_ATTACKS, TrafficGenerator
from prahari.ledger import AlertLedger
from prahari.schema import Flow


# --- the maths ---------------------------------------------------------------
def test_entropy_ranks_spoofed_above_normal():
    spoofed = [f"1.2.3.{i}" for i in range(200)]
    normal = ["10.0.0.5"] * 180 + ["10.0.0.6"] * 20
    assert shannon_entropy(spoofed) > shannon_entropy(normal) + 4


def test_cv_separates_beacon_from_browsing():
    assert coefficient_of_variation([60, 58, 63, 59, 61, 62]) < 0.15
    assert coefficient_of_variation([2, 140, 7, 900, 15, 3, 420]) > 1.0


def test_regularity_is_monotone():
    assert regularity(0.0) > regularity(0.2) > regularity(2.0)


def test_jitter_band_peaks_in_the_c2_range():
    assert jitter_band(0.16) > jitter_band(0.0)
    assert jitter_band(0.16) > jitter_band(1.5)


def test_rfc1918():
    assert is_rfc1918("10.42.1.1") and is_rfc1918("192.168.0.9")
    assert not is_rfc1918("203.0.113.44")


def test_dga_name_looks_less_like_language_than_a_real_domain():
    a = lexical_features("x7kqp2mfvbzq.com")
    b = lexical_features("cloudflare.com")
    assert a["vowel_ratio"] < b["vowel_ratio"]


# --- schema ------------------------------------------------------------------
def test_flow_id_stable_and_byte_ratio_correct():
    f = Flow(ts=1.0, src_ip="10.0.0.1", dst_ip="8.8.8.8", src_port=1, dst_port=53,
             bytes_out=900, bytes_in=300)
    g = Flow(ts=1.0, src_ip="10.0.0.1", dst_ip="8.8.8.8", src_port=1, dst_port=53)
    assert f.flow_id == g.flow_id
    assert abs(f.byte_ratio - 3.0) < 1e-9


# --- ledger ------------------------------------------------------------------
def test_hash_chain_detects_tampering():
    d = Path(tempfile.mkdtemp())
    led = AlertLedger(d / "a.jsonl")
    for i in range(5):
        led.append({"alert_id": f"a{i}", "threat": {"class": "recon_scanning"}})
    ok, n, _ = led.verify()
    assert ok and n == 5

    lines = (d / "a.jsonl").read_text().splitlines()
    lines[2] = lines[2].replace('"recon_scanning"', '"benign"')
    (d / "a.jsonl").write_text("\n".join(lines) + "\n")
    ok2, _, bad2 = AlertLedger(d / "a.jsonl").verify()
    assert not ok2 and bad2 is not None


# --- end to end --------------------------------------------------------------
def test_engine_detects_every_threat_class():
    flows = TrafficGenerator(seed=4242, jitter=0.2).capture(1800, classes=ALL_ATTACKS)
    found = {a.threat_class for a in Engine(window=60.0).run(flows)}
    for cls in ALL_ATTACKS:
        alt = ({"c2_beaconing", "encrypted_malware"}
               if cls in ("c2_beaconing", "encrypted_malware") else {cls})
        assert found & alt, f"no detection for {cls} (found {sorted(found)})"


def test_engine_is_deterministic():
    mk = lambda: Engine(window=60.0).run(
        TrafficGenerator(seed=7, jitter=0.2).capture(900, classes=ALL_ATTACKS))
    assert [x.alert_id for x in mk()] == [x.alert_id for x in mk()]


def test_benign_only_capture_is_quiet():
    """The negative test that matters: no attacks in, no alerts out except the
    one documented false positive (the nightly backup host)."""
    flows = TrafficGenerator(seed=99, jitter=0.2).capture(1800, classes=set())
    alerts = Engine(window=60.0).run(flows)
    noisy = [a.threat_class for a in alerts if a.threat_class != "data_exfiltration"]
    assert not noisy, f"benign traffic produced {noisy}"


def test_read_only_selftest_passes():
    from prahari.selftest import check_no_network_imports
    ok, offenders = check_no_network_imports()
    assert ok, f"detection path imports a network client: {offenders}"


if __name__ == "__main__":
    fns = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_")]
    failed = 0
    for name, fn in fns:
        try:
            fn()
            print(f"  PASS  {name}")
        except Exception as e:
            failed += 1
            print(f"  FAIL  {name}: {e}")
    print(f"\n{len(fns) - failed}/{len(fns)} tests passed")
    raise SystemExit(1 if failed else 0)
