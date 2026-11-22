"""ELRS frequency-hopping sequence generation.

Ported verbatim from ExpressLRS:

  src/lib/FHSS/random.cpp   rng(), rngSeed(), rngN()
  src/lib/FHSS/FHSS.cpp     FHSSrandomiseFHSSsequenceBuild(), domains[]
  src/lib/FHSS/FHSS.h       FHSS_SEQUENCE_LEN = 256

The LCG is deliberately weak (32-bit state, only 15 output bits) and the
lower half of the seed produces a duplicate sequence -- exactly the weakness
Fox-IT exploited to recover the last UID byte from observed hop timing.
"""

from __future__ import annotations

from dataclasses import dataclass

FHSS_SEQUENCE_LEN = 256
LCG_A = 214013
LCG_C = 2531011
LCG_M = 2147483648  # 2**31


@dataclass(frozen=True)
class Domain:
    name: str
    freq_start_hz: int
    freq_stop_hz: int
    freq_count: int
    sync_channel: int

    @property
    def freq_spread_hz(self) -> float:
        return (self.freq_stop_hz - self.freq_start_hz) / (self.freq_count - 1)

    @property
    def sequence_len(self) -> int:
        return (FHSS_SEQUENCE_LEN // self.freq_count) * self.freq_count

    def channel_hz(self, index: int) -> int:
        return round(self.freq_start_hz + self.freq_spread_hz * index)

    def channel_index(self, hz: int) -> int:
        return round((hz - self.freq_start_hz) / self.freq_spread_hz)


# Sub-GHz domains from FHSS.cpp.  The Glytch Mesh Mod's E22 SX1262 covers
# 850-930 MHz so both the 868 and 915 domains are reachable; the operator
# selects the regulatory domain matching the target link.
DOMAINS = {
    "AU915": Domain("AU915", 915_500_000, 926_900_000, 20, 10),
    "FCC915": Domain("FCC915", 903_500_000, 926_900_000, 40, 20),
    "EU868": Domain("EU868", 863_275_000, 869_575_000, 13, 6),
    "IN866": Domain("IN866", 865_375_000, 866_950_000, 4, 2),
    "AU433": Domain("AU433", 433_420_000, 434_420_000, 3, 1),
    "EU433": Domain("EU433", 433_100_000, 434_450_000, 3, 1),
    "US433": Domain("US433", 433_250_000, 438_000_000, 8, 4),
    "US433W": Domain("US433W", 423_500_000, 438_000_000, 20, 10),
    "TH920": Domain("TH920", 920_500_000, 924_700_000, 8, 4),
}


class LCG:
    """The exact LCG from random.cpp."""

    __slots__ = ("seed",)

    def __init__(self, seed: int = 0):
        self.seed = seed & 0xFFFFFFFF

    def rng(self) -> int:
        self.seed = (LCG_A * self.seed + LCG_C) % LCG_M
        return self.seed >> 16

    def rng_n(self, maximum: int) -> int:
        return self.rng() % maximum


def build_sequence(seed: int, domain: Domain) -> list[int]:
    """FHSSrandomiseFHSSsequenceBuild(): 256-entry hop index sequence."""
    freq_count = domain.freq_count
    sync_channel = domain.sync_channel
    sequence_count = (FHSS_SEQUENCE_LEN // freq_count) * freq_count
    rng = LCG(seed)

    seq = [0] * sequence_count
    for i in range(sequence_count):
        m = i % freq_count
        if m == 0:
            seq[i] = sync_channel
        elif m == sync_channel:
            seq[i] = 0
        else:
            seq[i] = m

    for i in range(sequence_count):
        if i % freq_count == 0:
            continue
        offset = (i // freq_count) * freq_count
        rand = rng.rng_n(freq_count - 1) + 1
        seq[i], seq[offset + rand] = seq[offset + rand], seq[i]

    return seq


def sequence_from_uid(uid: bytes, domain: Domain, ota_version: int = 4,
                      uid_seed_fn=None) -> list[int]:
    """Build the FHSS sequence for a recovered UID."""
    if uid_seed_fn is None:
        from .crypto import uid_seed as uid_seed_fn  # type: ignore
    return build_sequence(uid_seed_fn(uid, ota_version), domain)


def sync_frequency(domain: Domain) -> int:
    """Frequency the sync channel sits on (Hz), no AFC correction."""
    return domain.channel_hz(domain.sync_channel)
