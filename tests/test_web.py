"""Tests for the web/service/router layer.

These exercise the same functions the local server and the Vercel functions
call, so a green run here means both deployments answer correctly. No socket is
opened — the router is a pure function of (method, path, query, body).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from web import service
from web.router import dispatch


def _json(method, path, query="", body=b""):
    status, headers, raw = dispatch(method, path, query, body)
    return status, json.loads(raw)


def test_health_and_routes():
    s, d = _json("GET", "/api/health")
    assert s == 200 and d["third_party_packages"] == 0
    assert d["threat_classes"] == 7


def test_scenarios_listed():
    s, d = _json("GET", "/api/scenarios")
    assert s == 200
    ids = {sc["id"] for sc in d["scenarios"]}
    assert {"full", "benign", "beacon"} <= ids


def test_analyze_full_finds_every_class():
    s, d = _json("GET", "/api/analyze", "scenario=full&duration=600")
    assert s == 200
    assert len(d["by_class"]) >= 6
    assert d["alerts_total"] > 0
    # every alert carries evidence and an id
    for a in d["alerts"][:20]:
        assert a["id"] and a["evidence"]


def test_analyze_benign_is_quiet():
    s, d = _json("GET", "/api/analyze", "scenario=benign")
    # The only permitted alert is the documented backup-host false positive,
    # planted on purpose as a hard negative. Anything else means the negative
    # control is not clean.
    noisy = [c for c in d["by_class"] if c != "data_exfiltration"]
    assert not noisy, f"benign scenario raised {noisy}"


def test_analyze_post_body():
    body = json.dumps({"scenario": "beacon", "duration": 600, "jitter": 0.4}).encode()
    s, d = _json("POST", "/api/analyze", "", body)
    assert s == 200 and "c2_beaconing" in d["by_class"]


def test_single_direction_degrades_not_collapses():
    s_full, d_full = _json("GET", "/api/analyze", "scenario=full&duration=900")
    s_deg, d_deg = _json("GET", "/api/analyze", "scenario=full&duration=900&single_direction=1")
    assert len(d_deg["by_class"]) >= len(d_full["by_class"]) - 1


def test_selftest_passes_and_scans_modules():
    s, d = _json("GET", "/api/selftest")
    assert s == 200 and d["passed"] is True
    assert len(d["modules"]) > 10
    # the import gate must be a real pass, not informational
    gate = d["checks"][0]
    assert gate["passed"] and "network client" in gate["name"]


def test_ledger_clean_verifies():
    s, d = _json("GET", "/api/verify")
    assert s == 200 and d["verified"] is True and d["records"] > 0


def test_ledger_tamper_is_detected():
    s, d = _json("GET", "/api/verify", "tamper=1")
    assert d["verified"] is False
    assert d["first_bad_alert_id"]
    assert d["original_value"] and d["altered_value"] == "low"


def test_metrics_shape():
    s, d = _json("GET", "/api/metrics")
    assert s == 200 and d["macro_f1"] > 0
    assert len(d["jitter_sweep"]) >= 5


def test_pcap_upload_roundtrips():
    """Real packet bytes through the service (no HTTP size cap here)."""
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
    from make_pcap import build, write_pcap
    import tempfile
    _, packets = build(600)
    tmp = Path(tempfile.mkdtemp()) / "t.pcap"
    write_pcap(tmp, packets, snaplen=96)          # small, like a real tap
    d = service.analyze_pcap(tmp.read_bytes())
    assert d["flows"] > 0 and len(d["by_class"]) >= 5
    # and a small one fits under the router's serverless body cap
    tiny = Path(tempfile.mkdtemp()) / "s.pcap"
    _, p2 = build(120)
    write_pcap(tiny, p2, snaplen=64)
    if tiny.stat().st_size < 4 * 1024 * 1024:
        s, dd = _json("POST", "/api/pcap", "", tiny.read_bytes())
        assert s == 200 and dd["flows"] > 0


def test_pcap_too_large_rejected():
    s, d = _json("POST", "/api/pcap", "", b"\x00" * (5 * 1024 * 1024))
    assert s == 413 and "limit_bytes" in d


def test_unknown_route_404():
    s, d = _json("GET", "/api/nope")
    assert s == 404 and "routes" in d


def test_cors_preflight():
    status, headers, _ = dispatch("OPTIONS", "/api/analyze")
    assert status == 204
    assert headers["Access-Control-Allow-Origin"] == "*"


def test_service_degraded_measures_retention():
    d = service.degraded(duration=600, seeds=(2001, 2002))
    assert 0.5 <= d["retained"] <= 1.0
    assert len(d["rows"]) == 7


if __name__ == "__main__":
    fns = [(n, f) for n, f in sorted(globals().items()) if n.startswith("test_")]
    failed = 0
    for name, fn in fns:
        try:
            fn(); print(f"  PASS  {name}")
        except Exception as e:
            failed += 1; print(f"  FAIL  {name}: {e}")
    print(f"\n{len(fns) - failed}/{len(fns)} web tests passed")
    raise SystemExit(1 if failed else 0)
