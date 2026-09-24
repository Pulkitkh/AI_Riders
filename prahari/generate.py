"""Synthetic traffic generator.

Produces a time-ordered, fully labelled stream of flow records covering benign
traffic plus the six threat classes named in SIH26145. Everything is seeded, so
a given seed reproduces the exact same capture — which is what makes the
evaluation in eval/ meaningful rather than anecdotal.

Deliberate design choice: the benign classes include the things that *look like*
attacks. Monitoring pollers beacon. Backup windows invert the byte ratio. Asset
scanners fan out. If the benign traffic were clean, the detectors would score
perfectly and the numbers would be worthless.
"""
from __future__ import annotations

import math
import random
import string

from .schema import Flow

# --- environment shape -------------------------------------------------------
INTERNAL = [f"10.42.{s}.{h}" for s in (1, 3, 7, 9) for h in range(2, 30)]
WEB_DSTS = ["104.18.32.7", "142.250.183.14", "13.107.42.14", "151.101.65.69",
            "20.190.159.4", "99.84.66.12"]
DNS_SERVER = "10.42.0.53"
NTP_SERVER = "10.42.0.123"
BACKUP_DST = "10.42.0.200"

# JA4-style fingerprints. The common ones belong to browsers and OS stacks; a
# rare one on a single host is the lead worth chasing.
JA4_COMMON = ["t13d1516h2_8daaf6152771_02713d6af862",
              "t13d1517h2_8daaf6152771_b0da82dd1658",
              "t12d1916h1_c866b44c5a26_5e3e5b1b2f1a"]
JA4_MALICIOUS = "t13d191100_9dc949149365_97f8aa674fd9"

COMMON_WORDS = ["cdn", "api", "mail", "static", "login", "cloud", "assets",
                "portal", "update", "images", "secure", "download", "app"]
TLDS = ["com", "net", "org", "in", "io"]


def _rand_name(rng: random.Random, n: int) -> str:
    return "".join(rng.choice(string.ascii_lowercase + "0123456789") for _ in range(n))


def _benign_domain(rng: random.Random) -> str:
    return f"{rng.choice(COMMON_WORDS)}{rng.choice(['', '-1', '2', ''])}.{_pick_brand(rng)}.{rng.choice(TLDS)}"


def _pick_brand(rng: random.Random) -> str:
    return rng.choice(["google", "microsoft", "akamai", "cloudflare", "amazonaws",
                       "github", "ubuntu", "nic", "gov"])


class TrafficGenerator:
    def __init__(self, seed: int = 1337, jitter: float = 0.20, n_beacons: int = 3):
        self.rng = random.Random(seed)
        self.jitter = jitter          # C2 beacon jitter fraction, 0.0 .. 0.5
        self.n_beacons = n_beacons    # distinct C2 pairs per capture

    # -- benign ---------------------------------------------------------------
    def _web(self, t: float) -> Flow:
        rng = self.rng
        src = rng.choice(INTERNAL)
        n_out = rng.randint(6, 30)
        n_in = rng.randint(20, 160)
        sizes = []
        for i in range(min(20, n_out + n_in)):
            sizes.append(rng.randint(120, 600) if i % 3 == 0 else -rng.randint(400, 1460))
        return Flow(ts=t, src_ip=src, dst_ip=rng.choice(WEB_DSTS),
                    src_port=rng.randint(32768, 61000), dst_port=443,
                    duration=rng.uniform(0.3, 14.0),
                    pkts_out=n_out, pkts_in=n_in,
                    bytes_out=n_out * rng.randint(120, 400),
                    bytes_in=n_in * rng.randint(700, 1400),
                    syn=1, synack=1, fin=1, pkt_sizes=sizes,
                    tls_ja4=rng.choice(JA4_COMMON),
                    tls_sni=_benign_domain(rng),
                    tls_cert_days=rng.choice([90, 365, 398]),
                    label="benign")

    def _dns(self, t: float) -> Flow:
        rng = self.rng
        return Flow(ts=t, src_ip=rng.choice(INTERNAL), dst_ip=DNS_SERVER,
                    src_port=rng.randint(32768, 61000), dst_port=53, proto="udp",
                    duration=rng.uniform(0.001, 0.05),
                    pkts_out=1, pkts_in=1,
                    bytes_out=rng.randint(60, 110), bytes_in=rng.randint(90, 380),
                    dns_qname=_benign_domain(rng), dns_qtype="A", dns_rcode="NOERROR",
                    label="benign")

    def _poller(self, t: float, src: str, dst: str, port: int) -> Flow:
        """Monitoring agent. Periodic *by design* — the beaconing false positive."""
        rng = self.rng
        return Flow(ts=t, src_ip=src, dst_ip=dst, src_port=rng.randint(32768, 61000),
                    dst_port=port, duration=rng.uniform(0.01, 0.12),
                    pkts_out=4, pkts_in=4,
                    bytes_out=rng.randint(300, 420), bytes_in=rng.randint(280, 500),
                    syn=1, synack=1, fin=1,
                    pkt_sizes=[220, -260, 180, -240],
                    tls_ja4=JA4_COMMON[0], tls_sni="monitor.internal.nic",
                    tls_cert_days=365, label="benign")

    def _backup(self, t: float, src: str) -> Flow:
        """Nightly backup. Byte ratio inverts — the exfiltration false positive."""
        rng = self.rng
        n = rng.randint(3000, 9000)
        return Flow(ts=t, src_ip=src, dst_ip=BACKUP_DST,
                    src_port=rng.randint(32768, 61000), dst_port=445,
                    duration=rng.uniform(20, 120),
                    pkts_out=n, pkts_in=int(n * 0.05),
                    bytes_out=n * rng.randint(900, 1400), bytes_in=n * rng.randint(40, 80),
                    syn=1, synack=1, fin=1, label="benign")

    # -- attacks --------------------------------------------------------------
    def _syn_flood(self, t: float, dst: str, n: int) -> list[Flow]:
        rng = self.rng
        out = []
        for i in range(n):
            spoof = f"{rng.randint(11,223)}.{rng.randint(0,255)}.{rng.randint(0,255)}.{rng.randint(1,254)}"
            out.append(Flow(ts=t + i * 0.0008, src_ip=spoof, dst_ip=dst,
                            src_port=rng.randint(1024, 65535), dst_port=443,
                            duration=0.0, pkts_out=1, pkts_in=0,
                            bytes_out=60, bytes_in=0, syn=1, synack=0,
                            label="volumetric_ddos"))
        return out

    def _beacon(self, t: float, src: str, dst: str) -> Flow:
        """C2 check-in: small, similar every time, on a jittered interval."""
        rng = self.rng
        base = rng.randint(180, 260)
        return Flow(ts=t, src_ip=src, dst_ip=dst, src_port=rng.randint(32768, 61000),
                    dst_port=443, duration=rng.uniform(0.05, 0.3),
                    pkts_out=5, pkts_in=4,
                    bytes_out=base + rng.randint(-12, 12),
                    bytes_in=base + rng.randint(-20, 20),
                    syn=1, synack=1, fin=1,
                    pkt_sizes=[200, -180, 210, -190, 205],
                    tls_ja4=JA4_MALICIOUS, tls_sni=None,
                    tls_self_signed=True, tls_cert_days=7,
                    label="c2_beaconing")

    def _dga(self, t: float, src: str, resolves: bool) -> Flow:
        rng = self.rng
        name = f"{_rand_name(rng, rng.randint(12, 22))}.{rng.choice(['com','net','info','biz'])}"
        return Flow(ts=t, src_ip=src, dst_ip=DNS_SERVER,
                    src_port=rng.randint(32768, 61000), dst_port=53, proto="udp",
                    duration=rng.uniform(0.002, 0.04), pkts_out=1, pkts_in=1,
                    bytes_out=70 + len(name), bytes_in=90 if resolves else 75,
                    dns_qname=name, dns_qtype="A",
                    dns_rcode="NOERROR" if resolves else "NXDOMAIN",
                    label="dga_resolution")

    def _tunnel(self, t: float, src: str, parent: str) -> Flow:
        rng = self.rng
        chunk = ".".join(_rand_name(rng, rng.randint(28, 46)) for _ in range(rng.randint(2, 3)))
        name = f"{chunk}.{parent}"
        return Flow(ts=t, src_ip=src, dst_ip=DNS_SERVER,
                    src_port=rng.randint(32768, 61000), dst_port=53, proto="udp",
                    duration=rng.uniform(0.003, 0.05), pkts_out=1, pkts_in=1,
                    bytes_out=60 + len(name), bytes_in=rng.randint(300, 900),
                    dns_qname=name[:250], dns_qtype=rng.choice(["TXT", "TXT", "NULL", "CNAME"]),
                    dns_rcode="NOERROR", label="dns_tunnelling")

    def _mal_tls(self, t: float, src: str, dst: str) -> Flow:
        rng = self.rng
        sizes = []
        for i in range(18):                      # long upload-shaped conversation
            sizes.append(rng.randint(1200, 1460) if i % 4 else -rng.randint(60, 140))
        return Flow(ts=t, src_ip=src, dst_ip=dst, src_port=rng.randint(32768, 61000),
                    dst_port=443, duration=rng.uniform(4, 40),
                    pkts_out=rng.randint(120, 400), pkts_in=rng.randint(20, 60),
                    bytes_out=rng.randint(180_000, 900_000), bytes_in=rng.randint(4_000, 20_000),
                    syn=1, synack=1, fin=1, pkt_sizes=sizes,
                    tls_ja4=JA4_MALICIOUS, tls_sni=None,
                    tls_self_signed=True, tls_cert_days=rng.choice([3, 7, 14]),
                    label="encrypted_malware")

    def _scan(self, t: float, src: str, n: int) -> list[Flow]:
        rng = self.rng
        out, port = [], rng.randint(1, 200)
        for i in range(n):
            port = (port + rng.choice([1, 1, 1, 2, 3])) % 65500 + 1
            dst = rng.choice(INTERNAL)
            out.append(Flow(ts=t + i * 0.006, src_ip=src, dst_ip=dst,
                            src_port=rng.randint(40000, 60000), dst_port=port,
                            duration=0.0, pkts_out=1, pkts_in=0,
                            bytes_out=44, bytes_in=0, syn=1, synack=0,
                            label="recon_scanning"))
        return out

    def _exfil(self, t: float, src: str, dst: str) -> Flow:
        rng = self.rng
        n = rng.randint(400, 1800)
        return Flow(ts=t, src_ip=src, dst_ip=dst, src_port=rng.randint(32768, 61000),
                    dst_port=443, duration=rng.uniform(10, 90),
                    pkts_out=n, pkts_in=int(n * 0.03),
                    bytes_out=n * rng.randint(1100, 1440),
                    bytes_in=max(1, int(n * 0.03)) * rng.randint(60, 200),
                    syn=1, synack=1, fin=1,
                    tls_ja4=rng.choice(JA4_COMMON), tls_sni="storage-sync.example-cloud.com",
                    tls_cert_days=365, label="data_exfiltration")

    def _modbus(self, t: float, src: str, dst: str, func: int, write: bool = False,
                illegal: bool = False, label: str = "benign") -> Flow:
        """One Modbus/TCP request flow — an HMI poll, or an attacker's command."""
        rng = self.rng
        return Flow(ts=t, src_ip=src, dst_ip=dst, src_port=rng.randint(32768, 61000),
                    dst_port=502, duration=rng.uniform(0.01, 0.2),
                    pkts_out=2, pkts_in=2, bytes_out=rng.randint(66, 78),
                    bytes_in=rng.randint(70, 120), syn=1, synack=1, fin=1,
                    ics_proto="modbus", ics_func=func, ics_unit=rng.randint(1, 3),
                    ics_write=write, ics_illegal=illegal, label=label)

    # port and read/write function codes per OT protocol
    _ICS = {"modbus": (502, (1, 2, 3, 4, 7, 17), (5, 6, 16), 99),
            "iec104": (2404, (0x01, 0x03, 0x05, 0x07, 0x09), (0x2D, 0x2E, 0x2F), 0xFF),  # C_SC/C_DC/C_RC
            "dnp3": (20000, (0x01, 0x00, 0x09), (0x03, 0x04, 0x05), 0x0F)}                # func 3/4 = write/operate

    def _ics_flow(self, t: float, src: str, dst: str, proto: str, func: int,
                  write: bool = False, illegal: bool = False, label: str = "benign") -> Flow:
        rng = self.rng
        port = self._ICS[proto][0]
        return Flow(ts=t, src_ip=src, dst_ip=dst, src_port=rng.randint(32768, 61000),
                    dst_port=port, duration=rng.uniform(0.01, 0.2),
                    pkts_out=2, pkts_in=2, bytes_out=rng.randint(60, 90),
                    bytes_in=rng.randint(70, 130), syn=1, synack=1, fin=1,
                    ics_proto=proto, ics_func=func, ics_unit=rng.randint(1, 3),
                    ics_write=write, ics_illegal=illegal, label=label)

    def _modbus(self, t: float, src: str, dst: str, func: int, write: bool = False,
                illegal: bool = False, label: str = "benign") -> Flow:
        return self._ics_flow(t, src, dst, "modbus", func, write, illegal, label)

    def _ics_attack(self, t0: float, src: str, plc: str, proto: str = "modbus") -> list[Flow]:
        """An OT intrusion, in any of the three protocols: enumerate function
        codes, issue unauthorised WRITE/operate commands, and one illegal code —
        the classic ICS kill-chain from a host that never legitimately polled the
        controller. Same shape for Modbus, IEC 60870-5-104 and DNP3."""
        reads, writes, illegal = self._ICS[proto][1], self._ICS[proto][2], self._ICS[proto][3]
        flows = []
        for i, fc in enumerate(reads):
            flows.append(self._ics_flow(t0 + i * 0.6, src, plc, proto, fc, label="ics_intrusion"))
        flows.append(self._ics_flow(t0 + 4.0, src, plc, proto, illegal, illegal=True,
                                    label="ics_intrusion"))
        for i in range(6):
            fc = self.rng.choice(writes)
            flows.append(self._ics_flow(t0 + 5.0 + i * 0.8, src, plc, proto, fc, write=True,
                                        label="ics_intrusion"))
        return flows

    # -- the capture ----------------------------------------------------------
    def capture(self, duration_s: int = 1800, t0: float = 0.0,
                classes: set[str] | None = None) -> list[Flow]:
        """Generate one labelled capture. Returns flows sorted by timestamp."""
        rng = self.rng
        on = classes if classes is not None else set()
        flows: list[Flow] = []

        # --- benign background -----------------------------------------------
        n_web = int(duration_s * 1.6)
        for _ in range(n_web):
            flows.append(self._web(t0 + rng.uniform(0, duration_s)))
        for _ in range(int(duration_s * 2.2)):
            flows.append(self._dns(t0 + rng.uniform(0, duration_s)))

        # Monitoring agents, update checks and NTP: strictly periodic benign
        # traffic. These are the hard negatives — a detector that only tests for
        # regularity will flag every one of them.
        pollers = [(INTERNAL[3], "10.42.0.10", 9100, 30.0),
                   (INTERNAL[11], "10.42.0.10", 9100, 60.0),
                   (INTERNAL[24], NTP_SERVER, 123, 64.0),
                   (INTERNAL[5], "10.42.0.10", 9100, 45.0),
                   (INTERNAL[13], "10.42.0.11", 8086, 90.0),
                   (INTERNAL[19], "10.42.0.11", 8086, 120.0),
                   (INTERNAL[27], "10.42.0.12", 514, 75.0),
                   (INTERNAL[2], NTP_SERVER, 123, 128.0)]
        for src, dst, port, period in pollers:
            k = 0
            while t0 + k * period < t0 + duration_s:
                flows.append(self._poller(t0 + k * period + rng.uniform(0, 0.4), src, dst, port))
                k += 1

        # a backup window that inverts the byte ratio, benignly
        for i in range(6):
            flows.append(self._backup(t0 + duration_s * 0.55 + i * 9, INTERNAL[6]))

        # benign OT: each controller is polled with reads by its established
        # master, forever — Modbus PLCs, an IEC-104 RTU, a DNP3 outstation. This
        # baseline is what makes an attacker's write "unauthorised".
        OT = [("10.42.0.50", "10.42.5.10", "modbus", (3, 4)),
              ("10.42.0.50", "10.42.5.11", "modbus", (3, 4)),
              ("10.42.0.51", "10.42.5.20", "iec104", (0x01, 0x03)),   # SCADA master -> RTU
              ("10.42.0.52", "10.42.5.30", "dnp3", (0x01, 0x00))]      # DNP3 master -> outstation
        for master, ctrl, proto, reads in OT:
            k = 0
            while t0 + k * 5.0 < t0 + duration_s:
                flows.append(self._ics_flow(t0 + k * 5.0 + rng.uniform(0, 0.3), master, ctrl,
                                            proto, rng.choice(reads)))
                k += 1

        # --- attacks ----------------------------------------------------------
        if "volumetric_ddos" in on:
            flows += self._syn_flood(t0 + duration_s * 0.30, "10.42.0.80", 2200)

        if "c2_beaconing" in on:
            c2 = [(INTERNAL[17], "203.0.113.44", 60.0),
                  (INTERNAL[9],  "198.51.100.23", 45.0),
                  (INTERNAL[31], "203.0.113.91", 90.0)][:self.n_beacons]
            for src, dst, period in c2:
                t = t0 + rng.uniform(0, period)
                while t < t0 + duration_s:
                    flows.append(self._beacon(t, src, dst))
                    t += period * (1.0 + rng.uniform(-self.jitter, self.jitter))

        if "dga_resolution" in on:
            src = INTERNAL[8]
            for i in range(120):
                tt = t0 + duration_s * 0.42 + i * rng.uniform(0.3, 1.2)
                if tt < t0 + duration_s:
                    flows.append(self._dga(tt, src, resolves=(i == 113)))

        if "dns_tunnelling" in on:
            src = INTERNAL[21]
            for i in range(260):
                tt = t0 + duration_s * 0.20 + i * rng.uniform(0.15, 0.5)
                if tt < t0 + duration_s:
                    flows.append(self._tunnel(tt, src, "tun.example-c2.net"))

        if "encrypted_malware" in on:
            src = INTERNAL[17]
            for i in range(14):
                flows.append(self._mal_tls(t0 + duration_s * 0.60 + i * 21, src, "198.51.100.77"))

        if "recon_scanning" in on:
            flows += self._scan(t0 + duration_s * 0.12, "10.42.9.2", 900)

        if "data_exfiltration" in on:
            src = INTERNAL[22]        # a dedicated host: a clean baseline, then bulk upload
            for i in range(9):
                flows.append(self._exfil(t0 + duration_s * 0.72 + i * 30, src, "198.51.100.77"))

        if "ics_intrusion" in on:
            # attacks across all three OT protocols, so a demo can show a real
            # Modbus, IEC-104 and DNP3 intrusion — not just one protocol.
            flows += self._ics_attack(t0 + duration_s * 0.66, "10.42.9.7", "10.42.5.10", "modbus")
            flows += self._ics_attack(t0 + duration_s * 0.70, "10.42.9.8", "10.42.5.20", "iec104")
            flows += self._ics_attack(t0 + duration_s * 0.74, "10.42.9.9", "10.42.5.30", "dnp3")

        flows.sort(key=lambda f: f.ts)
        return flows


ALL_ATTACKS = {"volumetric_ddos", "c2_beaconing", "dga_resolution", "dns_tunnelling",
               "encrypted_malware", "recon_scanning", "data_exfiltration", "ics_intrusion"}
