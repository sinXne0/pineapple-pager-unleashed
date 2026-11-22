"""ELRS binding-phrase -> UID derivation and CRC/seed helpers.

Ported verbatim from ExpressLRS source:

  src/lib/CONFIG/config.cpp   BindphraseConfigurable::SetBindPhrase()
  src/lib/OTA/OTA.cpp         OtaUpdateCrcInitFromUid(), OtaGetUidSeed()
  src/include/targets.h       OTA_VERSION_ID

The binding phrase is NOT a secret by design (it is anti-collision, not
security), but recovering the 6-byte UID from one over-air sync packet is
enough to follow the link's FHSS sequence.  ELRSJACK recovers that UID and,
optionally, the phrase itself from a wordlist.
"""

from __future__ import annotations

import hashlib

# From config.cpp: BIND_KEY[] = "-DMY_BINDING_PHRASE=\""
BIND_PREFIX = b'-DMY_BINDING_PHRASE="'
BIND_SUFFIX = b'"'
UID_LEN = 6

# OTA_VERSION_ID in src/include/targets.h (current stable).
OTA_VERSION_ID = 4

# CRC polynomials from src/lib/OTA/OTA.h
CRC14_POLY = 0x2E57   # OTA4 (8-byte packets)
CRC16_POLY = 0x3D65   # OTA8 (13-byte packets)


def uid_from_binding_phrase(phrase, ota_version: int = OTA_VERSION_ID) -> bytes:
    """Return the 6-byte UID ELRS derives from a binding phrase.

    >>> uid_from_binding_phrase("").hex()
    '000000000000'
    The MD5 construction is: MD5('-DMY_BINDING_PHRASE="' + phrase + '"')
    and the UID is the first UID_LEN bytes.  A blank phrase yields all zeroes
    (unbound) and is returned as-is, matching config.cpp.
    """
    if isinstance(phrase, str):
        phrase = phrase.encode("utf-8")
    if not phrase:
        return bytes(UID_LEN)
    digest = hashlib.md5(BIND_PREFIX + phrase + BIND_SUFFIX).digest()
    return digest[:UID_LEN]


def crc_initializer(uid: bytes, ota_version: int = OTA_VERSION_ID) -> int:
    """OtaCrcInitializer = ((UID[4]<<8)|UID[5]) ^ (OTA_VERSION_ID<<8)."""
    if len(uid) < UID_LEN:
        raise ValueError("uid must be at least 6 bytes")
    return ((uid[4] << 8) | uid[5]) ^ ((ota_version & 0xFF) << 8)


def uid_seed(uid: bytes, ota_version: int = OTA_VERSION_ID) -> int:
    """OtaGetUidSeed(): the 32-bit LCG seed that generates the FHSS sequence."""
    if len(uid) < UID_LEN:
        raise ValueError("uid must be at least 6 bytes")
    return (
        ((uid[2] << 24) & 0xFFFFFFFF)
        + ((uid[3] << 16) & 0xFFFFFFFF)
        + ((uid[4] << 8) & 0xFFFFFFFF)
        + (uid[5] ^ (ota_version & 0xFF))
    ) & 0xFFFFFFFF


def uid_is_bound(uid: bytes) -> bool:
    """OtaUidIsBound(): UID[2..5] non-zero means the link is bound."""
    return len(uid) >= UID_LEN and any(uid[2:UID_LEN])


def _build_crc_table(bits: int, poly: int) -> list[int]:
    bitmask = (1 << bits) - 1
    highbit = 1 << (bits - 1)
    table = []
    for i in range(256):
        crc = i << (bits - 8)
        for _ in range(8):
            crc = ((crc << 1) ^ (poly if crc & highbit else 0)) & 0xFFFF
        table.append(crc & bitmask)
    return table


_CRC14_TABLE = _build_crc_table(14, CRC14_POLY)
_CRC16_TABLE = _build_crc_table(16, CRC16_POLY)


def crc_calc(data: bytes, length: int, crc: int, bits: int = 14) -> int:
    """Reproduce Crc2Byte::calc() from src/lib/CRC/crc.cpp."""
    table = _CRC14_TABLE if bits == 14 else _CRC16_TABLE
    bitmask = (1 << bits) - 1
    for i in range(length):
        crc = ((crc << 8) ^ table[((crc >> (bits - 8)) ^ data[i]) & 0xFF]) & 0xFFFF
    return crc & bitmask
