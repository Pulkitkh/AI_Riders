"""Passive parsers for the industrial protocols NTRO and NCIIPC actually guard.

A network IDS that only understands DNS and TLS is blind on the plant floor.
The OT world speaks Modbus, DNP3 and IEC 60870-5-104, and an intrusion there —
an unauthorised WRITE to a breaker, a scan of function codes before an attack —
looks nothing like an IT intrusion. These parsers read the *headers* of those
protocols (function code, unit id, control field) with no payload interpretation
and no key material, exactly like the DNS/TLS readers: enough to see what the
command is, never enough to be the command.

Everything here is header-only and read-only; constraint (b) holds on the plant
floor as it does on the enterprise LAN.
"""
from __future__ import annotations

import struct

# Well-known OT ports.
MODBUS_PORT = 502
DNP3_PORT = 20000
IEC104_PORT = 2404
ICS_PORTS = {MODBUS_PORT, DNP3_PORT, IEC104_PORT}

# Modbus function codes that CHANGE state — the ones that matter on a control
# network. Reads (1-4) observe; these command.
MODBUS_WRITE_FUNCS = {5, 6, 15, 16, 22, 23}
MODBUS_READ_FUNCS = {1, 2, 3, 4, 7, 11, 12, 17, 20, 21, 24, 43}
MODBUS_VALID_FUNCS = MODBUS_WRITE_FUNCS | MODBUS_READ_FUNCS

_MODBUS_FUNC_NAME = {
    1: "Read Coils", 2: "Read Discrete Inputs", 3: "Read Holding Registers",
    4: "Read Input Registers", 5: "Write Single Coil", 6: "Write Single Register",
    15: "Write Multiple Coils", 16: "Write Multiple Registers",
    22: "Mask Write Register", 23: "Read/Write Multiple Registers",
    43: "Encapsulated Interface", 8: "Diagnostics", 17: "Report Server ID",
}


def parse_modbus(payload: bytes):
    """Modbus/TCP: the 7-byte MBAP header + function code (RFC-less, spec-fixed).

    MBAP = transaction id (2) · protocol id (2, always 0) · length (2) · unit (1),
    then the PDU whose first byte is the function code. Nothing past the function
    code is read.
    """
    if len(payload) < 8:
        return None
    try:
        txn, proto_id, length, unit = struct.unpack("!HHHB", payload[:7])
    except struct.error:
        return None
    if proto_id != 0 or length < 2 or length > 260:
        return None
    func = payload[7]
    is_exception = bool(func & 0x80)
    base = func & 0x7F
    return {
        "proto": "modbus",
        "func": base,
        "func_name": _MODBUS_FUNC_NAME.get(base, f"fn{base}"),
        "unit": unit,
        "is_write": base in MODBUS_WRITE_FUNCS,
        "is_valid": base in MODBUS_VALID_FUNCS,
        "is_exception": is_exception,
    }


def recognise_dnp3(payload: bytes):
    """DNP3 (IEEE 1815): the data-link layer starts 0x05 0x64. Read control byte
    and addresses only — enough to see a control request on a substation link."""
    if len(payload) < 10 or payload[0] != 0x05 or payload[1] != 0x64:
        return None
    ctrl = payload[3]
    func = ctrl & 0x0F                       # link-layer function
    try:
        dst, src = struct.unpack("!HH", payload[4:8])
    except struct.error:
        return None
    return {"proto": "dnp3", "func": func, "unit": dst, "src_addr": src,
            "is_write": func in (0x03, 0x04), "is_valid": True, "is_exception": False}


def recognise_iec104(payload: bytes):
    """IEC 60870-5-104: APCI starts 0x68, then a length and control field that
    distinguishes I/S/U frames. Control commands (C_SC/C_DC) ride in I-frames."""
    if len(payload) < 6 or payload[0] != 0x68:
        return None
    apdu_len = payload[1]
    if apdu_len < 4 or apdu_len > 253:
        return None
    c1 = payload[2]
    if c1 & 0x01 == 0:                        # I-format frame carries ASDU
        frame, is_write = "I", True
    elif c1 & 0x03 == 0x01:
        frame, is_write = "S", False
    else:
        frame, is_write = "U", False
    return {"proto": "iec104", "func": c1, "unit": 0, "frame": frame,
            "is_write": is_write, "is_valid": True, "is_exception": False}


def parse_ics(dport: int, sport: int, payload: bytes):
    """Dispatch to the right OT parser by port. Returns None for non-ICS."""
    if not payload:
        return None
    if dport == MODBUS_PORT or sport == MODBUS_PORT:
        return parse_modbus(payload)
    if dport == DNP3_PORT or sport == DNP3_PORT:
        return recognise_dnp3(payload)
    if dport == IEC104_PORT or sport == IEC104_PORT:
        return recognise_iec104(payload)
    return None
