"""Command line entry point.

    python -m prahari.cli replay      # run a capture through the engine
    python -m prahari.cli selftest    # prove the read-only properties
    python -m prahari.cli bench       # measure sustained throughput
"""
from __future__ import annotations

import argparse
import json
import sys
import time

from .engine import Engine
from .generate import ALL_ATTACKS, TrafficGenerator
from .ledger import AlertLedger
from .schema import SEVERITY_BY_CLASS

SEV_COLOUR = {"critical": "\033[1;97;41m", "high": "\033[1;31m",
              "medium": "\033[1;33m", "low": "\033[1;36m"}
RESET = "\033[0m"


def _fmt_alert(a) -> str:
    col = SEV_COLOUR.get(a.severity, "")
    ev = ", ".join(f"{k}={v}" for k, v in list(a.evidence.items())[:3])
    return (f"{col}{a.severity.upper():>8}{RESET}  {a.threat_class:<20} "
            f"conf {a.confidence:<5.2f} {a.src_ip:>15} → {str(a.dst_ip):<18} {ev[:78]}")


def cmd_replay(args) -> int:
    gen = TrafficGenerator(seed=args.seed, jitter=args.jitter)
    flows = gen.capture(args.duration, classes=ALL_ATTACKS)
    print(f"capture: {len(flows)} flows over {args.duration}s "
          f"(seed {args.seed}, C2 jitter {args.jitter:.0%})")
    print("-" * 118)

    ledger = AlertLedger(args.ledger) if args.ledger else None
    engine = Engine(window=args.window, ledger=ledger,
                    on_alert=lambda a: print(_fmt_alert(a)))
    engine.run(flows)

    print("-" * 118)
    stats = engine.stats.summary()
    print("ENGINE  " + "  ".join(f"{k}={v}" for k, v in stats.items()))

    incidents = engine.fusion.ranked_incidents()
    multi = [i for i in incidents if len(i.classes) > 1]
    if multi:
        print(f"\nCORRELATED INCIDENTS ({len(multi)} host(s) showing more than one stage)")
        for inc in multi[:5]:
            print(f"  {inc.entity:>15}  severity={inc.severity:<8} score={inc.score:.2f}  "
                  f"chain: {' → '.join(inc.classes)}")
    if ledger:
        ok, n, bad = ledger.verify()
        print(f"\nLEDGER  {n} alerts, hash chain {'VERIFIED' if ok else f'BROKEN at {bad}'}")
    return 0


def cmd_selftest(args) -> int:
    from .selftest import main as selftest_main
    return selftest_main()


def cmd_bench(args) -> int:
    """Constraint (d): state and demonstrate the rate you were tested against."""
    gen = TrafficGenerator(seed=5, jitter=0.2)
    flows = []
    for i in range(args.captures):
        # contiguous in time — a benchmark with idle gaps measures the gaps
        flows += gen.capture(args.duration, t0=i * args.duration, classes=ALL_ATTACKS)
    flows.sort(key=lambda f: f.ts)
    print(f"benchmark: replaying {len(flows)} flows through the full pipeline ...")
    engine = Engine(window=args.window)
    engine.run(flows)
    s = engine.stats.summary()
    print(json.dumps(s, indent=2))
    print(f"\nSUSTAINED: {s['flows_per_sec']:.0f} flows/sec  |  "
          f"detection latency p50 {s['latency_p50_ms']:.0f} ms, "
          f"p95 {s['latency_p95_ms']:.0f} ms, p99 {s['latency_p99_ms']:.0f} ms")
    print("NOTE: latency is bounded below by the window size — a detector that "
          "aggregates over 60 s cannot alert faster than 60 s, and claiming "
          "otherwise would be incoherent.")
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="prahari", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("replay", help="replay a synthetic capture through the engine")
    r.add_argument("--duration", type=int, default=1800)
    r.add_argument("--seed", type=int, default=1337)
    r.add_argument("--jitter", type=float, default=0.20)
    r.add_argument("--window", type=float, default=60.0)
    r.add_argument("--ledger", default="data/alerts.jsonl")
    r.set_defaults(func=cmd_replay)

    s = sub.add_parser("selftest", help="prove the read-only constraints")
    s.set_defaults(func=cmd_selftest)

    b = sub.add_parser("bench", help="measure sustained throughput and latency")
    b.add_argument("--duration", type=int, default=1800)
    b.add_argument("--captures", type=int, default=6)
    b.add_argument("--window", type=float, default=60.0)
    b.set_defaults(func=cmd_bench)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
