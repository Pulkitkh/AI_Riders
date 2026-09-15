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


# --- real packet bytes -------------------------------------------------------
def _demo_pcap(duration: int = 600):
    """Build a genuine wire-format capture and read it back.

    Cached per duration so the round-trip tests below share one build.
    """
    key = f"_pcap_{duration}"
    if key not in globals():
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
        from make_pcap import build, write_pcap
        from prahari.pcapread import flows_from_capture
        flows, packets = build(duration)
        tmp = Path(tempfile.mkdtemp()) / "t.pcap"
        write_pcap(tmp, packets)
        globals()[key] = (flows, flows_from_capture(tmp), tmp)
    return globals()[key]


def test_pcap_round_trip_recovers_every_flow():
    """Packets in, the same flows back out — same count, same 5-tuples, in order.

    This is the test that makes the rest of the system credible on real traffic:
    the detectors were built against generated flow records, and this asserts
    that parsing actual Ethernet/IPv4/TCP bytes yields those same records.
    """
    orig, got, _ = _demo_pcap()
    assert len(got) == len(orig)
    key = lambda f: (f.src_ip, f.dst_ip, f.src_port, f.dst_port, f.proto)
    assert [key(f) for f in got] == [key(f) for f in orig]


def test_pcap_recovers_application_metadata_exactly():
    """DNS names, TLS fingerprints and certificate facts survive the wire.

    JA3 is recomputed from the ClientHello bytes rather than copied, and the
    certificate fields are parsed out of real DER, so an equality here is a
    statement about the parsers, not about the fixture.
    """
    orig, got, _ = _demo_pcap()
    for field in ("dns_qname", "dns_qtype", "dns_rcode", "tls_sni",
                  "tls_self_signed", "tls_cert_days"):
        mismatched = sum(1 for a, b in zip(orig, got)
                         if getattr(a, field) != getattr(b, field))
        assert mismatched == 0, f"{field}: {mismatched} flows differ after round trip"
    assert sum(1 for a, b in zip(orig, got) if bool(a.tls_ja4) != bool(b.tls_ja4)) == 0


def test_ja3_is_computed_not_copied():
    """A different ClientHello must produce a different fingerprint."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
    from make_pcap import tls_client_hello, DEFAULT_CIPHERS, DEFAULT_EXTS, DEFAULT_CURVES
    from prahari.pcapread import parse_tls_client_hello
    a = parse_tls_client_hello(tls_client_hello("x.example", DEFAULT_CIPHERS,
                                                DEFAULT_EXTS, DEFAULT_CURVES))
    b = parse_tls_client_hello(tls_client_hello("x.example", DEFAULT_CIPHERS[:3],
                                                DEFAULT_EXTS, DEFAULT_CURVES))
    assert a and b
    assert a["sni"] == "x.example"
    assert a["ja3_hash"] != b["ja3_hash"], "fingerprint ignored the cipher list"
    assert len(a["ja3_hash"]) == 32


def test_self_signed_certificate_is_recognised():
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
    from make_pcap import tls_server_certificate
    from prahari.pcapread import parse_tls_certificate
    ss = parse_tls_certificate(tls_server_certificate(
        "evil.test", "evil.test", (2026, 1, 1), (2026, 1, 8)))
    ca = parse_tls_certificate(tls_server_certificate(
        "good.test", "Some Real CA", (2026, 1, 1), (2027, 1, 1)))
    assert ss == {"self_signed": True, "cert_days": 7}
    assert ca["self_signed"] is False and ca["cert_days"] == 365


def test_byte_counts_follow_the_ip_header_not_the_snaplen():
    """A truncated capture must still account bytes correctly.

    Passive taps capture with a snaplen; if the reader counted captured bytes
    instead of the length the IP header declares, every volume-based detector
    would under-read on exactly the captures that matter.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
    from make_pcap import build, write_pcap
    from prahari.pcapread import flows_from_capture
    _, packets = build(300)
    tmpdir = Path(tempfile.mkdtemp())
    full, snapped = tmpdir / "full.pcap", tmpdir / "snap.pcap"
    write_pcap(full, packets, snaplen=262144)
    write_pcap(snapped, packets, snaplen=96)
    a, b = flows_from_capture(full), flows_from_capture(snapped)
    assert len(a) == len(b)
    assert [f.bytes_out for f in a] == [f.bytes_out for f in b]
    assert snapped.stat().st_size < full.stat().st_size


def test_detectors_fire_on_real_packet_bytes():
    """Every threat class the synthetic path finds is also found from packets."""
    orig, got, _ = _demo_pcap(1800)
    from_packets = {a.threat_class for a in Engine(window=60.0).run(got)}
    from_records = {a.threat_class for a in Engine(window=60.0).run(orig)}
    assert from_records <= from_packets, (
        f"lost on real bytes: {sorted(from_records - from_packets)}")
    assert len(from_packets) >= 6


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
