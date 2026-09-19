"""Precompute what the hosted demo should not compute per request.

Scenario analyses, the held-out metrics and the degraded-mode comparison are
deterministic, so they are baked into JSON at build time. The dashboard loads
instantly from these, and the live API endpoints remain available for anything
a judge wants to run themselves with different parameters.

    python3 -m web.build
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from web import service                              # noqa: E402

OUT = Path(__file__).resolve().parent / "public" / "data"


def write(name: str, payload: dict | list) -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(payload, separators=(",", ":"), allow_nan=False)
    (OUT / name).write_text(raw, encoding="utf-8")
    return len(raw)


def main() -> int:
    t0 = time.time()
    total = 0
    print("precomputing demo data ...")

    total += write("scenarios.json", service.list_scenarios())
    print(f"  scenarios.json")

    index = []
    for sid in service.SCENARIOS:
        r = service.analyze(sid)
        n = write(f"scenario-{sid}.json", r)
        total += n
        index.append({"id": sid, "title": r["title"], "alerts": r["alerts_total"],
                      "flows": r["flows"], "bytes": n})
        print(f"  scenario-{sid}.json   {r['flows']:>6} flows  "
              f"{r['alerts_total']:>3} alerts  {n/1024:>6.0f} KB")

    total += write("metrics.json", service.metrics())
    print("  metrics.json")

    deg = service.degraded(duration=1800, seeds=(2001, 2002, 2003, 2004, 2005))
    total += write("degraded.json", deg)
    print(f"  degraded.json        {deg['total_one_way']}/{deg['total_both']} retained")

    total += write("selftest.json", service.selftest())
    print("  selftest.json")

    total += write("index.json", {"scenarios": index,
                                  "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                                time.gmtime())})
    print(f"\n{total/1024:.0f} KB written to {OUT} in {time.time()-t0:.1f}s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
