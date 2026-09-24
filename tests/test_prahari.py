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

    lines = (d / "a.jsonl").read_text(encoding="utf-8").splitlines()
    lines[2] = lines[2].replace('"recon_scanning"', '"benign"')
    (d / "a.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
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
    """The negative test that matters: no attacks in, no alerts out — including
    the nightly-backup host, whose inverted byte ratio used to be the one
    documented false positive. The learned exfil model separates it from real
    exfiltration on `dst_external` (the backup goes to an internal file server),
    so the negative control is now completely silent."""
    flows = TrafficGenerator(seed=99, jitter=0.2).capture(1800, classes=set())
    alerts = Engine(window=60.0).run(flows)
    noisy = [(a.threat_class, a.src_ip) for a in alerts]
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


def test_ja4_is_spec_formatted_and_discriminates():
    """A real JA4: t + version + d/i + counts + ALPN _ hash _ hash, and it must
    change when the cipher/extension list changes (JA3's shuffle weakness fixed)."""
    import re
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
    from make_pcap import (tls_client_hello, DEFAULT_CIPHERS, DEFAULT_EXTS,
                           DEFAULT_CURVES, ODD_CIPHERS, ODD_EXTS)
    from prahari.pcapread import parse_tls_client_hello
    a = parse_tls_client_hello(tls_client_hello("x.example", DEFAULT_CIPHERS, DEFAULT_EXTS, DEFAULT_CURVES))
    b = parse_tls_client_hello(tls_client_hello(None, ODD_CIPHERS, ODD_EXTS, [0x17, 0x18]))
    assert re.match(r"^[tq]\d{2}[di]\d{2}\d{2}.._[0-9a-f]{12}_[0-9a-f]{12}$", a["ja4"])
    assert a["ja4"][3] == "d" and b["ja4"][3] == "i"      # SNI present vs absent
    assert a["ja4"] != b["ja4"]


def test_quic_initial_recognised_without_decryption():
    """QUIC must not be invisible: the long-header Initial is identified from
    public fields alone, no key material."""
    import struct
    from prahari.pcapread import parse_quic_initial
    pkt = bytes([0xC3]) + struct.pack("!I", 1) + bytes([8]) + bytes(range(8)) + bytes([0]) + b"\x00" * 20
    q = parse_quic_initial(pkt)
    assert q and q["is_initial"] and q["version"] == 1 and q["marker"] == "quic-v1"
    # a TLS-over-TCP record must NOT be mistaken for QUIC
    assert parse_quic_initial(b"\x16\x03\x01\x00\x40\x01") is None


def test_quic_crypto_matches_rfc9001_known_answers():
    """The Initial keys are derived from PUBLIC values, so they must equal the
    exact vectors published in RFC 9001 Appendix A.1 — and AES the FIPS-197 one.
    This is what proves we decrypt with no secret, correctly."""
    from prahari.quic_crypto import (_initial_secrets, _encrypt_block,
                                     _expand_key, INITIAL_SALT_V1)
    key, iv, hp = _initial_secrets(bytes.fromhex("8394c8f03e515708"), INITIAL_SALT_V1)
    assert key.hex() == "1f369613dd76d5467730efcbe3b1a22d"
    assert iv.hex() == "fa044b2f42a3fd3b46fb255c"
    assert hp.hex() == "9f50449e04a0e810283a1e9933adedd2"
    ct = _encrypt_block(_expand_key(bytes.fromhex("000102030405060708090a0b0c0d0e0f")),
                        bytes.fromhex("00112233445566778899aabbccddeeff"))
    assert ct.hex() == "69c4e0d86a7b0430d8cdb78070b4c55a"


def test_quic_initial_is_decrypted_to_a_real_ja4():
    """End to end: a genuine QUIC Initial is sealed, then decrypted with only the
    public salt, and the ClientHello inside yields a spec 'q…' JA4 plus its SNI —
    no key material, exactly as constraint (b) requires."""
    import re
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
    from make_pcap import tls_client_hello, DEFAULT_CIPHERS, DEFAULT_EXTS, DEFAULT_CURVES
    from prahari.quic_crypto import build_initial, decrypt_client_hello
    from prahari.pcapread import parse_tls_client_hello

    record = tls_client_hello("chat.quic.example", DEFAULT_CIPHERS, DEFAULT_EXTS, DEFAULT_CURVES)
    handshake = record[5:]                                  # strip the TLS record header
    pkt = build_initial(bytes.fromhex("8394c8f03e515708"), handshake)
    rec = decrypt_client_hello(pkt)
    assert rec is not None
    tls = parse_tls_client_hello(rec, transport="q")
    assert tls["sni"] == "chat.quic.example"
    assert tls["ja4"].startswith("q")                       # QUIC transport prefix
    assert re.match(r"^q\d{2}[di]\d{2}\d{2}.._[0-9a-f]{12}_[0-9a-f]{12}$", tls["ja4"])
    # a non-Initial / non-QUIC datagram must decrypt to nothing, not crash
    assert decrypt_client_hello(b"\x16\x03\x01\x00\x05hello") is None


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
    assert len(from_packets) >= 7


# --- single-direction visibility ---------------------------------------------
def test_single_direction_keeps_most_classes():
    """The strict reading of "unidirectional" must degrade, not collapse.

    If only one direction of each flow is visible, the detectors that depend on
    server-side evidence have to fall back. This asserts the fallback actually
    works rather than trusting the slide that says it does.
    """
    from prahari.visibility import project_all
    flows = TrafficGenerator(seed=2001, jitter=0.2).capture(1800, classes=ALL_ATTACKS)
    full = {a.threat_class for a in Engine(window=60.0).run(flows)}
    degraded = {a.threat_class for a in Engine(window=60.0).run(project_all(flows))}
    assert len(full) >= 8
    assert len(degraded) >= 7, f"one-way visibility lost {sorted(full - degraded)}"


def test_projection_removes_every_server_side_field():
    from prahari.visibility import project
    f = Flow(ts=0.0, src_ip="10.0.0.1", dst_ip="1.1.1.1", src_port=1234, dst_port=443,
             pkts_in=9, bytes_in=900, synack=1, rst=1, pkt_sizes=[100, -200, 300],
             dns_rcode="NXDOMAIN", tls_self_signed=True, tls_cert_days=7)
    g = project(f)
    assert (g.pkts_in, g.bytes_in, g.synack, g.rst) == (0, 0, 0, 0)
    assert g.pkt_sizes == [100, 300]
    assert g.dns_rcode is None and g.tls_cert_days is None
    assert g.tls_self_signed is False
    assert f.pkts_in == 9, "projection must not mutate the original flow"


def test_tls_detector_marks_degraded_alerts_honestly():
    """An alert raised without server-side evidence must say so."""
    from prahari.visibility import project_all
    flows = TrafficGenerator(seed=2002, jitter=0.2).capture(1800, classes=ALL_ATTACKS)
    alerts = [a for a in Engine(window=60.0).run(project_all(flows))
              if a.threat_class == "encrypted_malware"]
    assert alerts, "degraded TLS detection produced nothing at all"
    for a in alerts:
        assert a.evidence["server_side_observed"] is False
        assert "degraded" in a.caveat


def test_netflow_v5_ingest_roundtrips():
    """Exported flow records (NetFlow v5) map onto the same Flow the engine uses."""
    from prahari.netflow import build_v5, parse_v5
    dg = build_v5([
        {"src_ip": "10.0.0.5", "dst_ip": "8.8.8.8", "src_port": 40000, "dst_port": 443,
         "proto": "tcp", "bytes": 4096, "pkts": 20, "flags": 0x12},
        {"src_ip": "10.0.0.6", "dst_ip": "1.1.1.1", "src_port": 51000, "dst_port": 53,
         "proto": "udp", "bytes": 90, "pkts": 1},
    ])
    flows = parse_v5(dg)
    assert len(flows) == 2
    assert flows[0].src_ip == "10.0.0.5" and flows[0].dst_ip == "8.8.8.8"
    assert flows[0].proto == "tcp" and flows[0].bytes_out == 4096 and flows[0].synack == 1
    assert flows[1].proto == "udp" and flows[1].dst_port == 53


def test_udp_reflection_amplification_detected():
    """The reflection/amplification signature the PS names explicitly."""
    from prahari.detectors.ddos import DDoSDetector
    d = DDoSDetector()
    for i in range(200):
        d.observe(Flow(ts=i * 0.01, src_ip=f"9.9.{i % 254}.{(i * 7) % 254}",
                       dst_ip="10.0.0.80", src_port=53, dst_port=40000 + i,
                       proto="udp", pkts_out=1, bytes_out=3000))
    dets = d.evaluate(2.0)
    assert dets, "amplification flood not detected"
    assert dets[0].evidence["attack_kind"] == "udp_reflection_amplification"


def test_learned_exfil_uses_destination_locality():
    """The learned exfil model's whole reason to exist: a nightly backup inverts
    its byte ratio exactly like exfiltration, so no threshold on volume/ratio can
    separate them. Take a real exfil window's features and flip ONLY
    dst_external — same volume, same ratio, same concentration — and the score
    must collapse below the threshold. That is the separation a hand-set
    coefficient could never find and the model learned from labelled data."""
    from prahari.detectors.exfil import ExfilDetector
    d = ExfilDetector()
    if d.model is None:
        return                                  # clean checkout, heuristic fallback
    external = {"out_in_ratio": 50.0, "deviation": 11.15, "log_bytes_out": 6.42,
                "dst_concentration": 1.0, "dst_novelty": 0.0, "dst_external": 1.0,
                "out_share": 1.0, "n_flows": 3.0}
    internal = dict(external, dst_external=0.0)      # identical, but to an internal host
    p_ext = d.model.predict_proba(external)
    p_int = d.model.predict_proba(internal)
    assert p_ext >= d.threshold, f"external exfil not flagged ({p_ext:.2f})"
    assert p_int < d.threshold, f"internal upload wrongly flagged ({p_int:.2f})"
    assert p_ext - p_int > 0.5


def test_modbus_parser_reads_function_code_not_payload():
    """OT support: the Modbus/TCP header yields function code + write intent,
    header-only, and rejects a non-Modbus datagram."""
    import struct
    from prahari.icsparse import parse_modbus, parse_ics
    write = parse_modbus(struct.pack("!HHHB", 1, 0, 6, 1) + bytes([6, 0, 1, 0, 99]))
    assert write["proto"] == "modbus" and write["func"] == 6 and write["is_write"]
    read = parse_modbus(struct.pack("!HHHB", 2, 0, 6, 1) + bytes([3, 0, 0, 0, 10]))
    assert not read["is_write"] and read["is_valid"]
    illegal = parse_modbus(struct.pack("!HHHB", 3, 0, 2, 1) + bytes([99]))
    assert not illegal["is_valid"]
    assert parse_ics(443, 55000, b"\x16\x03\x01") is None      # not ICS


def test_iec104_and_dnp3_frames_parse():
    """OT breadth: genuine IEC 60870-5-104 and DNP3 frames are recognised as
    control traffic, from their real wire formats."""
    from prahari.icsparse import recognise_iec104, recognise_dnp3, parse_ics
    iec = bytes([0x68, 0x0e, 0x00, 0x00, 0x00, 0x00, 45, 0x01, 0x06, 0x00,
                 0x01, 0x00, 0x64, 0x00, 0x00, 0x01])          # I-frame, C_SC_NA_1
    r = recognise_iec104(iec)
    assert r and r["proto"] == "iec104" and r["frame"] == "I" and r["is_write"]
    dnp = bytes([0x05, 0x64, 0x14, 0xC4, 0x01, 0x00, 0x0A, 0x00, 0x00, 0x00])
    d = recognise_dnp3(dnp)
    assert d and d["proto"] == "dnp3" and d["func"] == 4       # operate/write
    assert parse_ics(2404, 33000, iec)["proto"] == "iec104"
    assert parse_ics(20000, 33000, dnp)["proto"] == "dnp3"


def test_ics_detector_flags_unauthorised_write_not_the_hmi():
    """The OT detector must catch an attacker's write/scan while leaving the
    established HMI's routine polling alone."""
    from prahari.detectors.ics import ICSDetector
    d = ICSDetector()
    # HMI establishes itself as the PLC's poller (reads)
    for i in range(6):
        d.observe(Flow(ts=i, src_ip="10.42.0.50", dst_ip="10.42.5.10", src_port=40000 + i,
                       dst_port=502, proto="tcp", ics_proto="modbus", ics_func=3))
    # attacker enumerates function codes then writes
    for i, fc in enumerate((1, 2, 4, 7, 17, 5, 6, 16)):
        d.observe(Flow(ts=10 + i, src_ip="10.42.9.9", dst_ip="10.42.5.10",
                       src_port=50000 + i, dst_port=502, proto="tcp", ics_proto="modbus",
                       ics_func=fc, ics_write=fc in (5, 6, 16)))
    dets = d.evaluate(30.0)
    hits = {x.src_ip for x in dets}
    assert "10.42.9.9" in hits, "attacker not flagged"
    assert "10.42.0.50" not in hits, "the HMI was wrongly flagged"


def test_isolation_forest_scores_attack_above_benign():
    """The unsupervised net separates an obvious outlier from normal traffic."""
    from prahari.anomaly import IsolationForest
    import random
    rng = random.Random(0)
    normal = [[rng.gauss(0, 1) for _ in range(6)] for _ in range(300)]
    iso = IsolationForest(n_trees=80, sample_size=128).fit(normal)
    s_normal = sum(iso.score([rng.gauss(0, 1) for _ in range(6)]) for _ in range(50)) / 50
    s_outlier = iso.score([12.0] * 6)
    assert s_outlier > s_normal
    # round-trips through JSON without changing a score
    d = iso.to_dict()
    assert abs(IsolationForest.from_dict(d).score([12.0] * 6) - s_outlier) < 1e-9


def test_alerts_carry_mitre_attack_technique():
    """Every alert lands in a MITRE ATT&CK technique an analyst can pivot on."""
    flows = TrafficGenerator(seed=4242, jitter=0.2).capture(1800, classes=ALL_ATTACKS)
    alerts = Engine(window=60.0).run(flows)
    assert alerts
    for a in alerts:
        assert "mitre_technique" in a.evidence and "mitre_tactic" in a.evidence


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
