"""ELRS OTA packet parsing/building (sync packets only).

Ported from ExpressLRS src/lib/OTA/OTA.h + OTA.cpp.  ELRSJACK deliberately
implements ONLY PACKET_TYPE_SYNC.  It never builds RCDATA (channel) packets:
there is no flight/vehicle control in this payload.  A crafted sync packet is
used solely for a link probe against an authorized bench receiver with no
actuator attached.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import crypto

PACKET_TYPE_SYNC = 0b10
PACKET_TYPE_DATA = 0b01
PACKET_TYPE_RCDATA = 0b00

OTA4_SIZE = 8
OTA8_SIZE = 13
OTA4_CRC_LEN = 7   # offsetof(OTA_Packet4_s, crcLow)
OTA8_CRC_LEN = 11  # offsetof(OTA_Packet8_s, crc)


@dataclass
class SyncPacket:
    uid4: int
    uid5: int
    fhss_index: int
    nonce: int
    rf_rate: int
    flags: int
    packet_size: int
    channel: int | None = None
    rssi_dbm: int | None = None
    crc_ok: bool = False

    @property
    def uid_tail(self) -> bytes:
        return bytes([self.uid4, self.uid5])


def _crc_std(payload: bytearray, initializer: int) -> int:
    """OTA4 CRC: zero crcHigh bits, calc over first 7 bytes, 14-bit poly."""
    work = bytearray(payload[:OTA4_CRC_LEN])
    work[0] &= 0x03
    return crypto.crc_calc(work, OTA4_CRC_LEN, initializer, bits=14)


def _crc_full(payload: bytearray, initializer: int) -> int:
    """OTA8 CRC: calc over first 11 bytes, 16-bit poly."""
    return crypto.crc_calc(payload[:OTA8_CRC_LEN], OTA8_CRC_LEN, initializer, bits=16)


def parse_sync(packet: bytes, channel: int | None = None,
               rssi_dbm: int | None = None) -> SyncPacket | None:
    """Parse and CRC-validate an ELRS OTA4 or OTA8 sync packet.

    Returns None if the packet is not a sync packet or the CRC does not
    validate.  CRC validation is what makes a captured UID trustworthy: a
    random LoRa packet from another device will not match the ELRS CRC
    derived from its own UID4/UID5.
    """
    if packet is None or len(packet) not in (OTA4_SIZE, OTA8_SIZE):
        return None
    if packet[0] & 0x03 != PACKET_TYPE_SYNC:
        return None

    if len(packet) == OTA4_SIZE:
        uid4, uid5 = packet[5], packet[6]
        sync = SyncPacket(
            uid4=uid4, uid5=uid5,
            fhss_index=packet[1], nonce=packet[2], rf_rate=packet[3],
            flags=packet[4] >> 2, packet_size=OTA4_SIZE,
            channel=channel, rssi_dbm=rssi_dbm,
        )
        work = bytearray(packet)
        work[0] &= 0x03
        initializer = crypto.crc_initializer(bytes([0, 0, 0, 0, uid4, uid5]))
        calculated = _crc_std(work, initializer)
        received = ((packet[0] >> 2) << 8) | packet[7]
        sync.crc_ok = (received == calculated)
    else:
        # OTA8: byte 0 is packetType (low 2 bits), sync follows at bytes 1-6.
        uid4, uid5 = packet[5], packet[6]
        sync = SyncPacket(
            uid4=uid4, uid5=uid5,
            fhss_index=packet[1], nonce=packet[2], rf_rate=packet[3],
            flags=packet[4] >> 2, packet_size=OTA8_SIZE,
            channel=channel, rssi_dbm=rssi_dbm,
        )
        initializer = crypto.crc_initializer(bytes([0, 0, 0, 0, uid4, uid5]))
        calculated = _crc_full(bytearray(packet), initializer)
        received = packet[11] | (packet[12] << 8)
        sync.crc_ok = (received == calculated)

    return sync if sync.crc_ok else None


def build_sync(uid: bytes, fhss_index: int, nonce: int = 0,
               rf_rate: int = 2, flags: int = 0, packet_size: int = OTA4_SIZE,
               ota_version: int = crypto.OTA_VERSION_ID) -> bytes:
    """Build a CRC-valid sync packet for a recovered UID.

    Used only by the authorized bench link probe.  No channel data is
    included: PACKET_TYPE_RCDATA is intentionally not implemented.
    """
    if len(uid) < crypto.UID_LEN:
        raise ValueError("uid must be at least 6 bytes")
    initializer = crypto.crc_initializer(uid, ota_version)

    if packet_size == OTA4_SIZE:
        body = bytearray([
            PACKET_TYPE_SYNC,
            fhss_index & 0xFF, nonce & 0xFF, rf_rate & 0xFF,
            (flags & 0x3F) << 2,
            uid[4], uid[5], 0,
        ])
        crc = _crc_std(body, initializer)
        # crcHigh is the 6-bit field at bits 2-7 of byte 0 in C; shift it left
        # by 2 when OR-ing into the raw byte.
        body[0] |= ((crc >> 8) & 0x3F) << 2
        body[7] = crc & 0xFF
        return bytes(body)
    elif packet_size == OTA8_SIZE:
        body = bytearray([
            PACKET_TYPE_SYNC,
            fhss_index & 0xFF, nonce & 0xFF, rf_rate & 0xFF,
            (flags & 0x3F) << 2,
            uid[4], uid[5],
            0, 0, 0, 0,  # free
            0, 0,        # crc
        ])
        crc = _crc_full(body, initializer)
        body[11] = crc & 0xFF
        body[12] = (crc >> 8) & 0xFF
        return bytes(body)
    raise ValueError("packet_size must be 8 or 13")
