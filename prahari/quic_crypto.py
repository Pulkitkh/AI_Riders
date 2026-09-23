"""Decrypt a QUIC Initial packet with nothing but the standard library.

A QUIC Initial is *encrypted*, but with keys the whole world already knows: RFC
9001 fixes a public "initial salt", and the client's Destination Connection ID
travels in the clear in the same packet. HKDF over those two public values
yields the exact AEAD key, IV and header-protection key the endpoints use for
the Initial. So a passive sensor can read the ClientHello inside a QUIC Initial
*without ever holding a secret* — the same way it reads a TLS-over-TCP
ClientHello, which is also sent in the clear.

That is the honest boundary this file sits on. It decrypts ONLY the Initial,
whose protection is keyed by public material; it never touches the 1-RTT keys
that protect the actual session, because those come from the (encrypted) key
exchange and cannot be derived passively. Reading the handshake is observation;
reading the session would be interception, and we do not do it.

Everything here is pure CPython — a compact AES-128 block cipher and RFC 5869
HKDF built on ``hmac``/``hashlib`` — so the zero-dependency guarantee holds even
for QUIC. AES-GCM is used in CTR mode only (we decrypt to recover the
ClientHello; the authentication tag is not verified, which is all a read-only
fingerprint needs).
"""
from __future__ import annotations

import hashlib
import hmac
import struct

# QUIC v1 Initial salt, RFC 9001 §5.2 — a published constant, not a secret.
INITIAL_SALT_V1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
# Draft-29 salt, still seen from older stacks.
INITIAL_SALT_D29 = bytes.fromhex("afbfec289993d24c9e9786f19c6111e04390a899")

# --- AES-128 (encrypt only; that is all CTR and header protection need) ------
_SBOX = (
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
)
_RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36)


def _xtime(a: int) -> int:
    a <<= 1
    return (a ^ 0x11b) & 0xff if a & 0x100 else a


def _expand_key(key: bytes) -> list[list[int]]:
    """AES-128 key schedule: 11 round keys of 16 bytes each."""
    words = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    for i in range(4, 44):
        t = list(words[i - 1])
        if i % 4 == 0:
            t = t[1:] + t[:1]                       # RotWord
            t = [_SBOX[b] for b in t]               # SubWord
            t[0] ^= _RCON[i // 4 - 1]
        words.append([words[i - 4][j] ^ t[j] for j in range(4)])
    return [sum(words[r:r + 4], []) for r in range(0, 44, 4)]


def _encrypt_block(rk: list[list[int]], block: bytes) -> bytes:
    s = [block[i] ^ rk[0][i] for i in range(16)]
    for rnd in range(1, 11):
        s = [_SBOX[b] for b in s]                   # SubBytes
        # ShiftRows (column-major state; row r shifts left by r)
        s = [s[0], s[5], s[10], s[15], s[4], s[9], s[14], s[3],
             s[8], s[13], s[2], s[7], s[12], s[1], s[6], s[11]]
        if rnd != 10:                               # MixColumns
            out = []
            for c in range(4):
                a = s[c * 4:c * 4 + 4]
                out += [
                    _xtime(a[0]) ^ (_xtime(a[1]) ^ a[1]) ^ a[2] ^ a[3],
                    a[0] ^ _xtime(a[1]) ^ (_xtime(a[2]) ^ a[2]) ^ a[3],
                    a[0] ^ a[1] ^ _xtime(a[2]) ^ (_xtime(a[3]) ^ a[3]),
                    (_xtime(a[0]) ^ a[0]) ^ a[1] ^ a[2] ^ _xtime(a[3]),
                ]
            s = out
        s = [s[i] ^ rk[rnd][i] for i in range(16)]  # AddRoundKey
    return bytes(s)


def _aes_ctr(key: bytes, nonce12: bytes, data: bytes) -> bytes:
    """AES-128 in GCM's counter arrangement: J0 = nonce || 1, stream from J0+1."""
    rk = _expand_key(key)
    out = bytearray()
    ctr = 2                                          # first plaintext block uses J0+1
    for off in range(0, len(data), 16):
        ks = _encrypt_block(rk, nonce12 + struct.pack("!I", ctr))
        chunk = data[off:off + 16]
        out += bytes(chunk[i] ^ ks[i] for i in range(len(chunk)))
        ctr += 1
    return bytes(out)


# --- HKDF (RFC 5869) and TLS 1.3 / QUIC label expansion ----------------------
def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def _expand_label(secret: bytes, label: str, length: int) -> bytes:
    full = b"tls13 " + label.encode()
    info = struct.pack("!H", length) + bytes([len(full)]) + full + b"\x00"
    return _hkdf_expand(secret, info, length)


# --- QUIC varint (RFC 9000 §16) ----------------------------------------------
def _varint(buf: bytes, off: int) -> tuple[int, int]:
    b = buf[off]
    n = 1 << (b >> 6)
    val = b & 0x3f
    for i in range(1, n):
        val = (val << 8) | buf[off + i]
    return val, off + n


def _initial_secrets(dcid: bytes, salt: bytes):
    initial = _hkdf_extract(salt, dcid)
    client = _expand_label(initial, "client in", 32)
    return (_expand_label(client, "quic key", 16),
            _expand_label(client, "quic iv", 12),
            _expand_label(client, "quic hp", 16))


def decrypt_client_hello(packet: bytes):
    """Recover the TLS ClientHello handshake bytes from a QUIC Initial.

    Returns the handshake message wrapped in a synthetic TLS record so the
    existing ``parse_tls_client_hello`` can read it unchanged, or None if the
    packet is not a decryptable v1/draft-29 Initial. Never raises.
    """
    try:
        if len(packet) < 7 or (packet[0] & 0xC0) != 0xC0:
            return None
        version = struct.unpack("!I", packet[1:5])[0]
        if version == 0x00000001:
            salt = INITIAL_SALT_V1
        elif version == 0xFF00001D:                  # draft-29
            salt = INITIAL_SALT_D29
        else:
            return None
        if (packet[0] & 0x30) >> 4 != 0:             # long-header type 0 = Initial
            return None

        off = 5
        dcid_len = packet[off]; off += 1
        dcid = packet[off:off + dcid_len]; off += dcid_len
        scid_len = packet[off]; off += 1
        off += scid_len
        token_len, off = _varint(packet, off)
        off += token_len
        length, off = _varint(packet, off)           # length of PN + payload
        pn_offset = off

        key, iv, hp = _initial_secrets(dcid, salt)

        # Header protection: a 16-byte sample 4 bytes past the PN masks the low
        # bits of byte 0 and the packet-number bytes (RFC 9001 §5.4).
        sample = packet[pn_offset + 4:pn_offset + 20]
        if len(sample) < 16:
            return None
        mask = _encrypt_block(_expand_key(hp), sample)
        first = packet[0] ^ (mask[0] & 0x0f)
        pn_len = (first & 0x03) + 1
        pn_bytes = bytes(packet[pn_offset + i] ^ mask[1 + i] for i in range(pn_len))
        pn = int.from_bytes(pn_bytes, "big")

        ct = packet[pn_offset + pn_len:pn_offset + length]
        if len(ct) <= 16:
            return None
        ct = ct[:-16]                                # drop the AEAD tag
        nonce = bytes(iv[i] ^ (pn.to_bytes(12, "big")[i]) for i in range(12))
        plain = _aes_ctr(key, nonce, ct)

        hs = _reassemble_crypto(plain)
        if not hs or hs[0] != 0x01:                  # ClientHello handshake type
            return None
        return b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs
    except (struct.error, IndexError, ValueError):
        return None


def build_initial(dcid: bytes, client_hello: bytes, pn: int = 2,
                  pad_to: int = 1200) -> bytes:
    """Encode a client QUIC v1 Initial carrying ``client_hello`` in a CRYPTO
    frame, protected exactly as an endpoint would. The inverse of
    ``decrypt_client_hello`` — used to synthesise genuine QUIC test traffic
    (make_pcap, the test suite) without a QUIC stack.
    """
    key, iv, hp = _initial_secrets(dcid, INITIAL_SALT_V1)
    clen = client_hello
    frame = b"\x06\x00" + _put_varint(len(clen)) + clen
    frame += b"\x00" * max(0, pad_to - len(frame) - 40)   # PADDING frames
    nonce = bytes(iv[i] ^ pn.to_bytes(12, "big")[i] for i in range(12))
    sealed = _aes_ctr(key, nonce, frame) + b"\x00" * 16    # placeholder AEAD tag
    pn_bytes = struct.pack("!H", pn)                        # 2-byte packet number
    length = len(pn_bytes) + len(sealed)
    hdr = (bytes([0xC1]) + struct.pack("!I", 1) + bytes([len(dcid)]) + dcid
           + b"\x00"                                        # scid length 0
           + b"\x00"                                        # token length 0
           + _put_varint(length))
    pkt = bytearray(hdr + pn_bytes + sealed)
    pn_off = len(hdr)
    mask = _encrypt_block(_expand_key(hp), bytes(pkt[pn_off + 4:pn_off + 20]))
    pkt[0] ^= mask[0] & 0x0f
    for i in range(2):
        pkt[pn_off + i] ^= mask[1 + i]
    return bytes(pkt)


def _put_varint(v: int) -> bytes:
    if v < 0x40:
        return bytes([v])
    if v < 0x4000:
        return struct.pack("!H", 0x4000 | v)
    if v < 0x40000000:
        return struct.pack("!I", 0x80000000 | v)
    return struct.pack("!Q", 0xC000000000000000 | v)


def _reassemble_crypto(plain: bytes) -> bytes:
    """Walk the decrypted frames and stitch CRYPTO fragments by offset."""
    chunks: dict[int, bytes] = {}
    off = 0
    n = len(plain)
    while off < n:
        ftype = plain[off]; off += 1
        if ftype == 0x00 or ftype == 0x01:           # PADDING / PING
            continue
        if ftype in (0x02, 0x03):                     # ACK — skip its fields
            _, off = _varint(plain, off)              # largest acked
            _, off = _varint(plain, off)              # ack delay
            rng, off = _varint(plain, off)            # ack range count
            _, off = _varint(plain, off)              # first ack range
            for _ in range(rng):
                _, off = _varint(plain, off)
                _, off = _varint(plain, off)
            if ftype == 0x03:
                for _ in range(3):
                    _, off = _varint(plain, off)
            continue
        if ftype == 0x06:                             # CRYPTO
            coff, off = _varint(plain, off)
            clen, off = _varint(plain, off)
            chunks[coff] = plain[off:off + clen]
            off += clen
            continue
        break                                         # unknown frame — stop cleanly
    if not chunks:
        return b""
    out = bytearray()
    for coff in sorted(chunks):
        if coff == len(out):
            out += chunks[coff]
    return bytes(out)
