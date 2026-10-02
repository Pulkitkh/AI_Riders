"""Loader for the NSL-KDD intrusion-detection benchmark.

NSL-KDD (Tavallaee et al., 2009) is the de-facto standard public dataset for
network intrusion detection: a cleaned version of KDD Cup '99 with the duplicate
records removed, so a classifier cannot win by memorising repeats. Each record is
a summarised network connection with 41 features and a label. Crucially, the test
set contains 17 attack types that appear in NO training record — a built-in,
real-world test of detecting *previously-unseen* attacks (exactly what an
anomaly-based IDS must do).

We parse it into the two shapes PRAHARI's own engine consumes:
  * `to_dict()` — a named feature dict for the logistic-regression classifier;
  * `to_vec()`  — a fixed-length numeric vector for the Isolation-Forest anomaly
                  detector.

No third-party libraries — the zero-dependency guarantee holds on real data too.
"""
from __future__ import annotations

import math
from pathlib import Path

# The 41 NSL-KDD feature names, in order (indices 0..40).
FEATURES = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]
CATEGORICAL = {1: "protocol_type", 2: "service", 3: "flag"}
# features whose raw magnitude spans many orders — log-scale them so one giant
# byte count does not dominate the Isolation Forest.
_LOG = {"duration", "src_bytes", "dst_bytes", "count", "srv_count",
        "dst_host_count", "dst_host_srv_count", "num_root", "num_compromised"}

# Attack name -> the five standard NSL-KDD categories.
_DOS = {"neptune", "smurf", "back", "teardrop", "pod", "land", "apache2",
        "processtable", "mailbomb", "udpstorm", "worm"}
_PROBE = {"satan", "ipsweep", "portsweep", "nmap", "mscan", "saint"}
_R2L = {"warezclient", "guess_passwd", "warezmaster", "imap", "ftp_write",
        "multihop", "phf", "spy", "sendmail", "named", "snmpgetattack",
        "snmpguess", "xlock", "xsnoop", "httptunnel", "worm"}
_U2R = {"buffer_overflow", "rootkit", "loadmodule", "perl", "sqlattack",
        "xterm", "ps"}

# proto / flag have few, fixed values — one-hot them for the IF vector. Service
# has ~70 values; for the fixed vector we fold it to a single "is-rare-service"
# style ordinal via hashing, and leave full one-hot to the dict classifier.
_PROTOS = ("tcp", "udp", "icmp")
_FLAGS = ("SF", "S0", "REJ", "RSTR", "RSTO", "SH", "S1", "S2", "S3", "OTH", "RSTOS0")


def category(attack: str) -> str:
    a = attack.strip().lower()
    if a == "normal":
        return "normal"
    if a in _DOS:
        return "dos"
    if a in _PROBE:
        return "probe"
    if a in _R2L:
        return "r2l"
    if a in _U2R:
        return "u2r"
    return "other"          # any unseen attack name still counts as an attack


class Record:
    __slots__ = ("raw", "label", "attack")

    def __init__(self, fields: list[str]):
        self.raw = fields[:41]
        self.attack = fields[41].strip().lower()
        self.label = 0 if self.attack == "normal" else 1

    def _num(self, i: int) -> float:
        try:
            return float(self.raw[i])
        except (ValueError, IndexError):
            return 0.0

    def to_dict(self) -> dict[str, float]:
        """Named feature dict for the logistic-regression classifier."""
        d: dict[str, float] = {}
        for i, name in enumerate(FEATURES):
            if i in CATEGORICAL:
                d[f"{name}={self.raw[i]}"] = 1.0
            else:
                v = self._num(i)
                d[name] = math.log10(v + 1.0) if name in _LOG else v
        return d

    def to_vec(self) -> list[float]:
        """Fixed-length numeric vector for the Isolation-Forest anomaly net."""
        vec: list[float] = []
        for i, name in enumerate(FEATURES):
            if i in CATEGORICAL:
                continue
            v = self._num(i)
            vec.append(math.log10(v + 1.0) if name in _LOG else v)
        vec += [1.0 if self.raw[1] == p else 0.0 for p in _PROTOS]
        vec += [1.0 if self.raw[3] == f else 0.0 for f in _FLAGS]
        return vec


def load(path: str | Path) -> list[Record]:
    p = Path(path)
    out: list[Record] = []
    for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        fields = line.split(",")
        if len(fields) >= 42:
            out.append(Record(fields))
    return out


def feature_dim() -> int:
    """Length of the fixed vector returned by Record.to_vec()."""
    return (len(FEATURES) - len(CATEGORICAL)) + len(_PROTOS) + len(_FLAGS)
