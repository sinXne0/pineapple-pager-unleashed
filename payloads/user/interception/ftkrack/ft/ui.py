#!/usr/bin/env python3
"""FTKRACK on-device UI (480x222).

Screens: INTRO -> TARGET -> CAPTURE -> REPLAY -> PROOF -> LOG.

The UI never drives the monitor socket.  It reads /tmp/ftkrack_state.json and
appends commands to /tmp/ftkrack_cmd.jsonl.  All radio work belongs to engine.py.

Dev machine:
    python3 ft/ui.py --headless --sample --frames 6
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
for _p in (ROOT, os.path.join(ROOT, "lib")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

STATE = os.environ.get("FTKRACK_STATE", "/tmp/ftkrack_state.json")
CMD = os.environ.get("FTKRACK_CMD", "/tmp/ftkrack_cmd.jsonl")


def rgb(r, g, b):
    return ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)


BLACK = 0x0000
WHITE = 0xFFFF
RED = rgb(255, 64, 64)
GREEN = rgb(0, 235, 130)
AMBER = rgb(255, 176, 32)
CYAN = rgb(0, 205, 255)
MAGENTA = rgb(238, 74, 200)
GRAY = rgb(110, 122, 118)
DARK = rgb(4, 8, 14)
PANEL = rgb(8, 20, 26)
GRID = rgb(0, 56, 62)

SCREENS = ["INTRO", "TARGET", "CAPTURE", "REPLAY", "PROOF", "LOG"]
IFACES = ["wlan1mon", "wlan0mon"]
COUNT_CHOICES = (1, 3, 5, 10)


class FakePager:
    BTN_UP, BTN_DOWN, BTN_LEFT, BTN_RIGHT = 0x01, 0x02, 0x04, 0x08
    BTN_A, BTN_B, BTN_POWER = 0x10, 0x20, 0x40
    EVENT_PRESS = 1

    def __init__(self, width=480, height=222):
        self.width, self.height = width, height
        self.frames = 0
        self.events = []
        self.texts = []

    def __enter__(self): return self
    def __exit__(self, *a): return False
    def init(self): pass
    def cleanup(self): pass
    def set_rotation(self, r): pass
    def clear(self, c=0): pass
    def flip(self): self.frames += 1
    def delay(self, ms): pass
    def get_input_event(self):
        if not self.events:
            return None
        ev = self.events.pop(0)
        if isinstance(ev, (tuple, list)):
            class E: pass
            e = E(); e.button, e.type = ev[0], ev[1]
            return e
        return ev
    def peek_buttons(self): return 0
    def clear_input_events(self): pass
    def fill_rect(self, *a): pass
    def rect(self, *a): pass
    def hline(self, *a): pass
    def vline(self, *a): pass
    def line(self, *a): pass
    def circle(self, *a): pass
    def fill_circle(self, *a): pass
    def pixel(self, *a): pass
    def draw_text(self, *a):
        if len(a) >= 3:
            self.texts.append(str(a[2]))
    def draw_text_centered(self, *a): pass
    def text_width(self, text, size=1): return len(str(text)) * 6 * size
    def led_rgb(self, *a): pass
    def led_dpad(self, *a): pass
    def led_all_off(self): pass


def load_state(path=None):
    try:
        with open(path or STATE, "r") as fh:
            obj = json.load(fh)
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def send_cmd(obj, path=None):
    try:
        with open(path or os.environ.get("FTKRACK_CMD", CMD), "a") as fh:
            fh.write(json.dumps(obj, separators=(",", ":")) + "\n")
        return True
    except Exception:
        return False


def event_parts(ev):
    """Normalise both PAGERCTL tuple events and FakePager objects."""
    if ev is None:
        return None
    if isinstance(ev, (tuple, list)):
        if len(ev) < 2:
            return None
        return int(ev[0]), int(ev[1])
    return int(getattr(ev, "button", 0)), int(getattr(ev, "type", 1))


def sample_state():
    return {
        "authorized": True, "phase": "idle", "iface": "wlan1mon",
        "monitor": "ok",
        "target": {"bssid": "a4:5e:60:11:22:33", "ssid": "CORP-FT"},
        "capture": {
            "captured": True, "frames_seen": 1284, "ft_requests": 3,
            "ssid": "CORP-FT", "sta": "3c:71:bf:aa:bb:cc", "mdid": 4660,
            "snonce": "10" * 32, "anonce": "30" * 32, "mic": "01" * 16,
            "channel_hz": 5180_000_000, "signal_dbm": -58, "raw_len": 141,
        },
        "replay": {"attempted": True, "frames": 3, "write_errors": 0,
                   "kernel_accepted": True, "count": 3, "last_error": ""},
        "response": {"observed": True, "status": 0, "aid": 2, "count": 2},
        "pn": {"before": 42, "before_max": 9731, "after": 12,
               "after_max": 9731, "reuse_exact": 3, "regression": 3},
        "proof": {
            "confirmed": True,
            "detail": "FT reassociation replay accepted; AP PTK/TK reinstall indicated",
            "reasons": [],
        },
        "logs": [
            "FTKRACK ready. Authorize before any capture or replay.",
            "Authorization accepted. Authorized testing only.",
            "Monitor ready on wlan1mon.",
            "FT reassoc request: AP=a4:5e:60:11:22:33 STA=3c:71:bf:aa:bb:cc",
            "Replay sent 3 frame(s) (153 bytes each), write errors=0.",
            "Reassoc response after replay: status=0",
            "CCMP PN evidence: reuse=3 regression=3",
            "PROOF: CONFIRMED - nonce reuse observed",
        ],
        "error": "", "seq": 31,
    }


class FtKrackUI:
    FPS_DELAY_MS = 80

    def __init__(self, pager):
        self.p = pager
        self.W, self.H = pager.width, pager.height
        self.state = None
        self.screen_idx = 0
        self.last_sent = 0.0

    @property
    def screen(self):
        return SCREENS[self.screen_idx]

    def text(self, x, y, s, color=WHITE, size=1):
        try:
            self.p.draw_text(x, y, str(s), color, size)
        except Exception:
            pass

    def header(self):
        p, W = self.p, self.W
        st = self.state or {}
        p.fill_rect(0, 0, W, 26, DARK)
        p.hline(0, 26, W, GRID)
        self.text(6, 6, "FTKRACK", MAGENTA, 2)
        phase = str(st.get("phase", "idle")).upper()
        mon = str(st.get("monitor", "none")).upper()
        self.text(96, 8, f"802.11r FT KEY REINSTALL / {phase} / MON={mon}", CYAN, 1)
        proof = st.get("proof") or {}
        led = GREEN if proof.get("confirmed") else (
            RED if st.get("error") else (
                AMBER if (st.get("capture") or {}).get("captured") else GRAY))
        p.fill_circle(W - 14, 13, 5, led)
        x = 6
        for i, tab in enumerate(SCREENS):
            color = MAGENTA if i == self.screen_idx else GRAY
            self.text(x, 30, tab, color, 1)
            x += 84

    def footer(self):
        p, W, H = self.p, self.W, self.H
        p.fill_rect(0, H - 22, W, 22, DARK)
        p.hline(0, H - 22, W, GRID)
        hints = {
            "INTRO": "A authorize   L/R screens",
            "TARGET": "U/D interface  A open monitor  B lock target from capture",
            "CAPTURE": "A sniff 10s  B clear evidence",
            "REPLAY": "U/D count  A replay captured FT reassoc request",
            "PROOF": "A verify evidence  B clear",
            "LOG": "L/R screens",
        }
        self.text(6, H - 17, hints.get(self.screen, ""), GRAY, 1)

    def draw_intro(self):
        st = self.state or {}
        p, W = self.p, self.W
        p.fill_rect(12, 52, W - 24, 134, PANEL)
        p.rect(12, 52, W - 24, 134, GRID)
        self.text(22, 58, "FTKRACK // 802.11r FT KEY REINSTALL", MAGENTA, 2)
        lines = [
            "Replays a captured FT Reassociation Request to force",
            "AP PTK/TK reinstallation and CCMP nonce reuse (CVE-2017-13082).",
            "",
            "Requires: Pager 2.0.0-stable+, MT7921 monitor (wlan1mon).",
            "No Mesh Mod. No extra hardware. Python stdlib only.",
            "No live target validation; success needs real observed proof.",
        ]
        for i, line in enumerate(lines):
            self.text(22, 80 + i * 13, line, GRAY, 1)
        self.text(22, 154, "AUTHORIZED TESTING ONLY", AMBER, 1)
        auth = bool(st.get("authorized"))
        label = "AUTHORIZED - press A to continue" if auth else "NOT AUTHORIZED - press A"
        self.text(22, 170, label, GREEN if auth else RED, 2)

    def draw_target(self):
        st = self.state or {}
        p, W = self.p, self.W
        self.text(8, 56, "MONITOR INTERFACE", AMBER, 1)
        for i, iface in enumerate(IFACES):
            color = MAGENTA if iface == st.get("iface") else GRAY
            self.text(10 + i * 120, 72, iface, color, 1)
        self.text(8, 96, f"status: {st.get('monitor', 'none')}", WHITE, 1)
        if st.get("monitor") in ("none", None, ""):
            self.text(8, 112, "ARPHRD 803 monitor required - set it in Pineapple UI", RED, 1)
        tgt = st.get("target") or {}
        p.fill_rect(12, 132, W - 24, 52, PANEL)
        p.rect(12, 132, W - 24, 52, GRID)
        self.text(22, 138, f"TARGET BSSID: {tgt.get('bssid') or '--'}", GREEN, 2)
        self.text(22, 162, f"SSID: {tgt.get('ssid') or '--'}", GRAY, 1)

    def draw_capture(self):
        st = self.state or {}
        cap = st.get("capture") or {}
        p, W = self.p, self.W
        p.fill_rect(12, 54, W - 24, 130, PANEL)
        p.rect(12, 54, W - 24, 130, GRID)
        self.text(24, 60, "FT REASSOCIATION CAPTURE", MAGENTA, 2)
        self.text(24, 82, f"frames seen: {cap.get('frames_seen', 0)}", GRAY, 1)
        self.text(24, 98, f"FT reassoc requests: {cap.get('ft_requests', 0)}",
                  GREEN if cap.get("captured") else AMBER, 2)
        self.text(24, 122, f"STA: {cap.get('sta') or '--'}", WHITE, 1)
        self.text(24, 138, f"MDID: {cap.get('mdid')}  CH: {cap.get('channel_hz', 0)}",
                  WHITE, 1)
        self.text(24, 154, f"raw frame bytes: {cap.get('raw_len', 0)}", GRAY, 1)
        if not cap.get("captured"):
            self.text(24, 170, "No valid FTIE/MDIE request yet.", RED, 1)

    def draw_replay(self):
        st = self.state or {}
        rep = st.get("replay") or {}
        p, W = self.p, self.W
        p.fill_rect(12, 56, W - 24, 128, PANEL)
        p.rect(12, 56, W - 24, 128, GRID)
        self.text(24, 64, "VERBATIM REASSOC REPLAY", MAGENTA, 2)
        self.text(24, 88, "Injects the captured management frame unchanged.", GRAY, 1)
        count = rep.get("count", 3)
        self.text(24, 112, f"count: {count}   (U/D to change)", AMBER, 2)
        status = "SENT" if rep.get("attempted") else "NOT RUN"
        self.text(24, 140, f"status: {status}  accepted={rep.get('frames', 0)}  "
                           f"write errors={rep.get('write_errors', 0)}", WHITE, 1)
        self.text(24, 160, "No data frames are generated by this tool.", GRAY, 1)

    def draw_proof(self):
        st = self.state or {}
        proof = st.get("proof") or {}
        rep = st.get("response") or {}
        pn = st.get("pn") or {}
        p, W = self.p, self.W
        p.fill_rect(12, 54, W - 24, 132, PANEL)
        p.rect(12, 54, W - 24, 132, GRID)
        self.text(24, 60, "REINSTALLATION PROOF", MAGENTA, 2)
        confirmed = bool(proof.get("confirmed"))
        self.text(24, 82, "CONFIRMED" if confirmed else "UNCONFIRMED",
                  GREEN if confirmed else AMBER, 2)
        self.text(24, 106, f"reassoc status-0 responses after replay: {rep.get('count', 0)}",
                  WHITE, 1)
        self.text(24, 122, f"CCMP PN before={pn.get('before', 0)} "
                           f"after={pn.get('after', 0)}", WHITE, 1)
        self.text(24, 138, f"reuse={pn.get('reuse_exact', 0)} "
                           f"regression={pn.get('regression', 0)}",
                  GREEN if (pn.get('reuse_exact') or pn.get('regression')) else AMBER, 1)
        detail = str(proof.get("detail", ""))[:70]
        self.text(24, 158, detail, GRAY, 1)

    def draw_log(self):
        logs = (self.state or {}).get("logs") or []
        for i, line in enumerate(logs[-9:]):
            self.text(8, 56 + i * 14, str(line)[:78], GRAY, 1)

    def render(self):
        p = self.p
        p.clear(BLACK)
        if self.state is None:
            p.fill_rect(0, 90, self.W, 40, PANEL)
            self.text(self.W // 2 - 100, 102, "Waiting for engine...", CYAN, 2)
        else:
            self.header()
            if self.screen == "INTRO": self.draw_intro()
            elif self.screen == "TARGET": self.draw_target()
            elif self.screen == "CAPTURE": self.draw_capture()
            elif self.screen == "REPLAY": self.draw_replay()
            elif self.screen == "PROOF": self.draw_proof()
            else: self.draw_log()
            self.footer()
        p.flip()

    def button(self, btn):
        now = time.time()
        if now - self.last_sent < 0.12:
            return
        self.last_sent = now
        st = self.state or {}

        if btn == self.p.BTN_LEFT:
            self.screen_idx = (self.screen_idx - 1) % len(SCREENS)
        elif btn == self.p.BTN_RIGHT:
            self.screen_idx = (self.screen_idx + 1) % len(SCREENS)
        elif btn == self.p.BTN_UP:
            if self.screen == "TARGET":
                idx = IFACES.index(st.get("iface")) if st.get("iface") in IFACES else 0
                send_cmd({"cmd": "iface", "value": IFACES[(idx - 1) % len(IFACES)]})
            elif self.screen == "REPLAY":
                cur = (st.get("replay") or {}).get("count", 3)
                idx = COUNT_CHOICES.index(cur) if cur in COUNT_CHOICES else 1
                send_cmd({"cmd": "count", "value": COUNT_CHOICES[(idx - 1) % len(COUNT_CHOICES)]})
        elif btn == self.p.BTN_DOWN:
            if self.screen == "TARGET":
                idx = IFACES.index(st.get("iface")) if st.get("iface") in IFACES else 0
                send_cmd({"cmd": "iface", "value": IFACES[(idx + 1) % len(IFACES)]})
            elif self.screen == "REPLAY":
                cur = (st.get("replay") or {}).get("count", 3)
                idx = COUNT_CHOICES.index(cur) if cur in COUNT_CHOICES else 1
                send_cmd({"cmd": "count", "value": COUNT_CHOICES[(idx + 1) % len(COUNT_CHOICES)]})
        elif btn == self.p.BTN_A:
            if self.screen == "INTRO":
                if not st.get("authorized"):
                    send_cmd({"cmd": "authorize"})
                else:
                    self.screen_idx = 1
            elif self.screen == "TARGET":
                send_cmd({"cmd": "monitor"})
            elif self.screen == "CAPTURE":
                send_cmd({"cmd": "sniff", "seconds": 10})
            elif self.screen == "REPLAY":
                send_cmd({"cmd": "replay"})
            elif self.screen == "PROOF":
                send_cmd({"cmd": "verify"})
        elif btn == self.p.BTN_B:
            if self.screen == "TARGET":
                send_cmd({"cmd": "autotarget"})
            elif self.screen == "CAPTURE":
                send_cmd({"cmd": "clear"})
            elif self.screen == "PROOF":
                send_cmd({"cmd": "clear"})
            else:
                self.screen_idx = 0

    def run(self):
        while True:
            st = load_state()
            if st is not None:
                self.state = st
            parts = event_parts(self.p.get_input_event())
            if parts is not None and parts[1] in (1, self.p.EVENT_PRESS):
                self.button(parts[0])
            self.render()
            self.p.delay(self.FPS_DELAY_MS)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--headless", action="store_true")
    ap.add_argument("--sample", action="store_true")
    ap.add_argument("--frames", type=int, default=0)
    args = ap.parse_args()
    pager = FakePager() if args.headless else None
    if pager is None:
        from pagerctl import Pager
        pager = Pager()
    with pager:
        pager.init()
        pager.set_rotation(270)
        ui = FtKrackUI(pager)
        if args.sample:
            ui.state = sample_state()
        if args.frames:
            for _ in range(args.frames):
                ui.render()
        else:
            ui.run()
        pager.led_all_off()
        pager.cleanup()


if __name__ == "__main__":
    main()
