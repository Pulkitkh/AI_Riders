"""Feature extraction and the small amount of maths the detectors need.

Pure standard library on purpose: the whole prototype must run on any laptop
with python3 and no pip install, which matters more at a demo than elegance.
"""
from __future__ import annotations

import math
from collections import Counter


# --- information theory ------------------------------------------------------
def shannon_entropy(items) -> float:
    """Entropy over a collection of hashables, in bits.

    Used two ways: over source IPs toward one destination (spoofed floods push
    it up) and over the characters of a domain name (DGA names push it up).
    """
    items = list(items)
    n = len(items)
    if n <= 1:
        return 0.0
    counts = Counter(items)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def normalised_entropy(items) -> float:
    """Entropy scaled to 0..1 against the maximum possible for that length."""
    items = list(items)
    if len(items) <= 1:
        return 0.0
    return shannon_entropy(items) / math.log2(len(set(items)) or 1) if len(set(items)) > 1 else 0.0


# --- descriptive statistics --------------------------------------------------
def mean(xs) -> float:
    xs = list(xs)
    return sum(xs) / len(xs) if xs else 0.0


def stdev(xs) -> float:
    xs = list(xs)
    if len(xs) < 2:
        return 0.0
    m = mean(xs)
    return math.sqrt(sum((x - m) ** 2 for x in xs) / (len(xs) - 1))


def coefficient_of_variation(xs) -> float:
    """sigma / mu. Low means regular. This is the primary beaconing feature:
    a fixed-interval beacon sits near 0, a 30%-jittered one near 0.17, and
    human-driven traffic is well above 1.0."""
    m = mean(xs)
    return stdev(xs) / m if m > 0 else 0.0


def median(xs) -> float:
    xs = sorted(xs)
    if not xs:
        return 0.0
    n = len(xs)
    return xs[n // 2] if n % 2 else (xs[n // 2 - 1] + xs[n // 2]) / 2


def mad(xs) -> float:
    """Median absolute deviation — survives a few missed check-ins in a way
    the standard deviation does not."""
    if not xs:
        return 0.0
    med = median(xs)
    return median([abs(x - med) for x in xs])


def autocorrelation_peak(xs, max_lag: int | None = None) -> float:
    """Strongest self-similarity at any lag >= 1. A repeating series scores high."""
    xs = list(xs)
    n = len(xs)
    if n < 4:
        return 0.0
    m = mean(xs)
    denom = sum((x - m) ** 2 for x in xs)
    if denom == 0:
        return 1.0
    max_lag = max_lag or max(1, n // 2)
    best = 0.0
    for lag in range(1, min(max_lag, n - 1) + 1):
        num = sum((xs[i] - m) * (xs[i + lag] - m) for i in range(n - lag))
        best = max(best, num / denom)
    return best


def intervals(timestamps) -> list[float]:
    ts = sorted(timestamps)
    return [b - a for a, b in zip(ts, ts[1:])]


# --- domain-name lexical features --------------------------------------------
VOWELS = set("aeiou")


def domain_labels(qname: str) -> list[str]:
    return [p for p in qname.split(".") if p]


def registrable_part(qname: str) -> str:
    """Rough eTLD+1. Good enough to group queries by parent domain, which is
    what the tunnelling detector aggregates on."""
    labels = domain_labels(qname)
    return ".".join(labels[-2:]) if len(labels) >= 2 else qname


def longest_consonant_run(s: str) -> int:
    best = cur = 0
    for ch in s:
        if ch.isalpha() and ch not in VOWELS:
            cur += 1
            best = max(best, cur)
        else:
            cur = 0
    return best


def lexical_features(qname: str, bigrams: dict[str, float] | None = None) -> dict[str, float]:
    """The feature vector the DGA classifier consumes."""
    labels = domain_labels(qname)
    sld = labels[0] if labels else ""
    body = "".join(c for c in sld if c.isalnum())
    n = max(len(body), 1)
    vowels = sum(1 for c in body if c in VOWELS)
    digits = sum(1 for c in body if c.isdigit())
    return {
        "length": float(len(sld)),
        "entropy": shannon_entropy(body),
        "vowel_ratio": vowels / n,
        "digit_ratio": digits / n,
        "consonant_run": float(longest_consonant_run(body)),
        "bigram_ll": bigram_log_likelihood(body, bigrams) if bigrams else 0.0,
        "n_labels": float(len(labels)),
    }


def bigram_table(corpus: list[str]) -> dict[str, float]:
    """Character bigram log-probabilities learned from benign domain names.

    This is the language model that separates 'cdn.cloudflare.com' from
    'x7kqp2mfvbz.com' — and it is fitted from data, not hand-tuned.
    """
    counts: Counter = Counter()
    total = 0
    for name in corpus:
        body = "^" + "".join(c for c in name.lower() if c.isalnum()) + "$"
        for a, b in zip(body, body[1:]):
            counts[a + b] += 1
            total += 1
    vocab = 38 * 38
    return {k: math.log((v + 1) / (total + vocab)) for k, v in counts.items()} | {
        "__default__": math.log(1 / (total + vocab))
    }


def bigram_log_likelihood(s: str, table: dict[str, float]) -> float:
    """Mean per-bigram log-probability. Low (very negative) means the name does
    not look like the domains this network normally resolves."""
    if not table:
        return 0.0
    body = "^" + s.lower() + "$"
    default = table.get("__default__", -12.0)
    pairs = list(zip(body, body[1:]))
    if not pairs:
        return default
    return sum(table.get(a + b, default) for a, b in pairs) / len(pairs)


def is_rfc1918(ip: str) -> bool:
    """Private address space. A monitoring agent talks to an internal collector;
    a C2 implant talks to the internet. Combined with prevalence this is one of
    the strongest legitimate separators available passively."""
    try:
        a, b, *_ = (int(x) for x in ip.split("."))
    except ValueError:
        return False
    return a == 10 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168)


# Recognised service / telemetry / update / CDN domains. Periodic, regular
# traffic to these is overwhelmingly legitimate background activity (OS and
# browser update checks, chat heartbeats, cloud sync). In a MULTI-host network
# destination popularity already separates these from C2; on a SINGLE-host tap
# (one laptop) that signal is degenerate — every destination is talked to by one
# host — so a recognised service SNI is what keeps normal use from looking like a
# beacon. This is a starter allowlist, not exhaustive; an operator extends it.
BENIGN_SNI_SUFFIXES = (
    "google.com", "googleapis.com", "gstatic.com", "gvt1.com", "gvt2.com",
    "youtube.com", "ytimg.com", "ggpht.com", "doubleclick.net",
    "microsoft.com", "windowsupdate.com", "windows.com", "office.com",
    "office365.com", "live.com", "msftconnecttest.com", "msedge.net", "bing.com",
    "apple.com", "icloud.com", "mzstatic.com", "cdn-apple.com",
    "mozilla.com", "mozilla.net", "firefox.com",
    "cloudflare.com", "cloudflare.net", "cloudflareinsights.com",
    "akamai.net", "akamaiedge.net", "akamaized.net", "fastly.net",
    "amazonaws.com", "cloudfront.net", "azureedge.net", "azure.com",
    "github.com", "githubusercontent.com", "githubassets.com",
    "slack.com", "slack-edge.com", "spotify.com", "scdn.co",
    "whatsapp.net", "facebook.com", "fbcdn.net", "instagram.com",
    "cloudflare-dns.com", "digicert.com", "letsencrypt.org", "sectigo.com",
    "ntp.org", "pool.ntp.org", "ubuntu.com", "debian.org", "canonical.com",
)


def is_benign_service_sni(sni: str | None) -> bool:
    """True if the SNI is under a recognised service/telemetry/CDN domain."""
    if not sni:
        return False
    host = sni.lower().rstrip(".")
    return any(host == s or host.endswith("." + s) for s in BENIGN_SNI_SUFFIXES)


def jitter_band(cv: float, centre: float = 0.16, width: float = 0.13) -> float:
    """How closely an interval CV matches the signature of a *jittered* beacon.

    This exists because CV is a band, not a threshold, and a linear model cannot
    express that on its own. A monitoring poller runs near-perfectly regular
    (CV close to zero); human-driven traffic is heavy-tailed (CV well above one);
    a C2 implant configured with 10-40% jitter sits in between. Scoring the
    distance to that band is what lets the classifier tell the three apart.
    """
    return math.exp(-(((cv - centre) / width) ** 2))


def regularity(cv: float) -> float:
    """How regular an interval series is, on 0..1, monotone in CV.

    Added after the jitter sweep in eval/ showed a blind spot: a model given
    only a band-shaped jitter feature learned "C2 means jittered", and therefore
    missed a *perfectly regular* beacon entirely — recall went to zero at 0%
    jitter. Regularity is high for anything repetitive, jittered or not, and the
    separation from benign monitoring agents is then carried by whether the
    destination is external and how many hosts talk to it.
    """
    return 1.0 / (1.0 + max(cv, 0.0))
