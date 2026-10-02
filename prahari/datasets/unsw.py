"""Loader for the UNSW-NB15 intrusion-detection benchmark.

UNSW-NB15 (Moustafa & Slay, 2015) is the modern successor to KDD/NSL-KDD: real
traffic captured on the Australian Centre for Cyber Security's IXIA testbed,
blending contemporary normal activity with nine attack families (Fuzzers,
Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, Worms).
It is the benchmark reviewers expect to see *because* NSL-KDD is derived from
1998 DARPA traffic — UNSW-NB15 answers "does this still hold on traffic from this
decade?". Each record is a summarised bidirectional flow with 42 features in the
official pre-split `UNSW_NB15_training-set.csv` / `UNSW_NB15_testing-set.csv`.

We parse it into the same two shapes the engine already consumes for NSL-KDD —
`to_dict()` for the logistic classifier and `to_vec()` for the Isolation Forest
and the autoencoder — so every model runs on it unchanged, no third-party
libraries. The loader is header-driven: it reads column names from the CSV header
rather than fixed positions, so a re-ordered export still loads correctly.
"""
from __future__ import annotations

import csv
import math
from pathlib import Path

CATEGORICAL = ("proto", "service", "state")
LABEL_COL = "label"
ATTACK_COL = "attack_cat"
# Columns never fed to a model (identifiers / targets).
_SKIP = {"id", LABEL_COL, ATTACK_COL}
# Heavy-tailed magnitudes: log-scale so one huge byte/rate value cannot dominate.
_LOG = {"dur", "sbytes", "dbytes", "rate", "sload", "dload", "spkts", "dpkts",
        "sinpkt", "dinpkt", "sjit", "djit", "stcpb", "dtcpb", "smean", "dmean",
        "response_body_len", "sloss", "dloss", "ct_srv_src", "ct_srv_dst"}

# The nine attack families in UNSW-NB15 (attack_cat values other than Normal).
FAMILIES = ("Fuzzers", "Analysis", "Backdoor", "DoS", "Exploits", "Generic",
            "Reconnaissance", "Shellcode", "Worms")
# bounded, enumerable one-hot vocabularies for the fixed anomaly vector
_PROTOS = ("tcp", "udp", "arp", "ospf", "icmp", "igmp", "sctp")
_STATES = ("FIN", "INT", "CON", "REQ", "RST", "ECO", "CLO", "URN", "no")


class Record:
    __slots__ = ("vals", "label", "attack")

    def __init__(self, row: dict[str, str]):
        self.vals = row
        self.attack = (row.get(ATTACK_COL) or "Normal").strip() or "Normal"
        try:
            self.label = int(float(row.get(LABEL_COL, 0)))
        except ValueError:
            self.label = 0 if self.attack.lower() == "normal" else 1

    def _num(self, key: str) -> float:
        try:
            return float(self.vals.get(key, 0.0) or 0.0)
        except ValueError:
            return 0.0

    def to_dict(self) -> dict[str, float]:
        """Named feature dict for the logistic-regression classifier."""
        d: dict[str, float] = {}
        for k, v in self.vals.items():
            if k in _SKIP:
                continue
            if k in CATEGORICAL:
                d[f"{k}={v}"] = 1.0
            else:
                x = self._num(k)
                d[k] = math.log10(x + 1.0) if (k in _LOG and x >= 0) else x
        return d

    def to_vec(self) -> list[float]:
        """Fixed-length numeric vector for the Isolation Forest / autoencoder."""
        vec: list[float] = []
        for k in _NUMERIC_ORDER:
            x = self._num(k)
            vec.append(math.log10(x + 1.0) if (k in _LOG and x >= 0) else x)
        proto = (self.vals.get("proto") or "").lower()
        state = (self.vals.get("state") or "")
        vec += [1.0 if proto == p else 0.0 for p in _PROTOS]
        vec += [1.0 if state == s else 0.0 for s in _STATES]
        return vec


# Canonical numeric-feature order (everything but id/label/attack_cat/categoricals),
# fixed so every vector is the same length regardless of dict iteration order.
_NUMERIC_ORDER = (
    "dur", "spkts", "dpkts", "sbytes", "dbytes", "rate", "sttl", "dttl", "sload",
    "dload", "sloss", "dloss", "sinpkt", "dinpkt", "sjit", "djit", "swin", "stcpb",
    "dtcpb", "dwin", "tcprtt", "synack", "ackdat", "smean", "dmean", "trans_depth",
    "response_body_len", "ct_srv_src", "ct_state_ttl", "ct_dst_ltm",
    "ct_src_dport_ltm", "ct_dst_sport_ltm", "ct_dst_src_ltm", "is_ftp_login",
    "ct_ftp_cmd", "ct_flw_http_mthd", "ct_src_ltm", "ct_srv_dst", "is_sm_ips_ports",
)


def category(attack: str) -> str:
    """Normalised family name, or 'normal'."""
    a = (attack or "").strip()
    return "normal" if a.lower() in ("", "normal") else a


def load(path: str | Path) -> list[Record]:
    p = Path(path)
    out: list[Record] = []
    with p.open("r", encoding="utf-8-sig", errors="ignore", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            if row.get(LABEL_COL) is None and row.get(ATTACK_COL) is None:
                continue
            out.append(Record(row))
    return out


def feature_dim() -> int:
    """Length of the fixed vector returned by Record.to_vec()."""
    return len(_NUMERIC_ORDER) + len(_PROTOS) + len(_STATES)
