#!/usr/bin/env python3
"""ELRSJACK on-device UI (480x222).

Screens: INTRO -> RADIO -> SCAN -> UID -> PROBE -> LOG.

The UI never drives the radio.  It reads /tmp/elrsjack_state.json and appends
commands to /tmp/elrsjack_cmd.jsonl.  All radio work belongs to the engine.

Dev machine:
    python3 elrs/ui.py --headless --sample --frames 5
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

from elrs import fhss  # noqa: E402

STATE = os.environ.get("ELRSJACK_STATE", "/tmp/elrsjack_state.json")
CMD = os.environ.get("ELRSJACK_CMD", "/tmp/elrsjack_cmd.jsonl")


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
SEL = rgb(0, 72, 64)
DIM = rgb(0, 96, 88)

SCREENS = ["INTRO", "RADIO", "SCAN", "TRACK", "UID", "PROBE", "LOG"]
DOMAINS = list(fhss.DOMAINS.keys())
RATES = ["200Hz", "100Hz", "50Hz", "25Hz"]


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
        if isinstance(ev, tuple):
            class E: pass
            e = E(); e.button, e.type = ev
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
        with open(path or os.environ.get("ELRSJACK_CMD", CMD), "a") as fh:
            fh.write(json.dumps(obj, separators=(",", ":")) + "\n")
        return True
    except Exception:
        return False


def sample_state():
    return {
        "authorized": True, "phase": "idle", "radio": "spi",
        "domain": "FCC915", "rate": "100Hz", "sync_word": "0x1212",
        "capture": {"raw_packets": 412, "valid_sync_packets": 7,
                    "sync_observations": 7, "last_uid_tail": [0x21, 0x55],
                    "sync_channel_hz": 915500000},
        "recovery": {"uid": "0000fd822155", "candidates": 2,
                     "candidate_uids": ["0000fd822155", "00007d822155"],
                     "observations": 5, "confirmed": True,
                     "method": "fhss-bruteforce"},
        "phrase": {"value": "test", "tested": 64, "confirmed": True},
        "probe": {"sent": True, "confirmed": True,
                  "detail": "downlink heard after sync probe"},
        "logs": ["ELRSJACK ready. Authorize to begin.",
                 "Radio ready on /dev/spidev1.0.",
                 "Sync packet OK: UID4/5=2155 idx=20 RSSI=-55",
                 "UID: 0000fd822155", "Phrase: test",
                 "PROBE: downlink heard after sync probe"],
        "error": "", "seq": 12,
    }


class ElrsJackUI:
    FPS_DELAY_MS = 80

    def __init__(self, pager):
        self.p = pager
        self.W, self.H = pager.width, pager.height
        self.state = None
        self.screen_idx = 0
        self.sel = 0
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
        p.hline(0, 26, W, DIM)
        self.text(6, 6, "ELRSJACK", MAGENTA, 2)
        phase = str(st.get("phase", "idle")).upper()
        radio = str(st.get("radio", "none")).upper()
        self.text(96, 8, f"900M LINK RECON / {phase} / {radio}", CYAN, 1)
        led = RED if st.get("error") else (
            GREEN if (st.get("phrase") or {}).get("confirmed") else
            AMBER if (st.get("capture") or {}).get("valid_sync_packets") else GRAY)
        p.fill_circle(W - 14, 13, 5, led)
        x = 6
        for i, tab in enumerate(SCREENS):
            color = MAGENTA if i == self.screen_idx else GRAY
            self.text(x, 30, tab, color, 1)
            x += 66

    def footer(self):
        p, W, H = self.p, self.W, self.H
        p.fill_rect(0, H - 22, W, 22, DARK)
        p.hline(0, H - 22, W, DIM)
        hints = {
            "INTRO": "A authorize   L/R screens",
            "RADIO": "U/D domain  L/R rate  A apply",
            "SCAN": "A scan 10s  B cycle sync word",
            "TRACK": "A park on one channel, record 20s of hops",
            "UID": "A recover  B crack phrase",
            "PROBE": "A bench link probe (no actuator)",
            "LOG": "L/R screens",
        }
        self.text(6, H - 17, hints.get(self.screen, ""), GRAY, 1)

    def draw_intro(self):
        st = self.state or {}
        p, W = self.p, self.W
        p.fill_rect(12, 52, W - 24, 134, PANEL)
        p.rect(12, 52, W - 24, 134, GRID)
        self.text(22, 58, "ELRSJACK // ELRS 900M LINK RECON", MAGENTA, 2)
        lines = [
            "Recovers the FHSS seed and binding phrase from",
            "one over-air sync packet plus hop timing.",
            "",
            "Hardware: Glytch Mesh Mod SX1262 (meshtasticd stopped)",
            "Scope: link-layer only. NO flight/vehicle control.",
        ]
        for i, line in enumerate(lines):
            self.text(22, 80 + i * 13, line, GRAY, 1)
        self.text(22, 145, "AUTHORIZED BENCH TESTING ONLY", AMBER, 1)
        auth = bool(st.get("authorized"))
        label = "AUTHORIZED - press A to continue" if auth else "NOT AUTHORIZED - press A"
        self.text(22, 166, label, GREEN if auth else RED, 2)

    def draw_radio(self):
        st = self.state or {}
        p, W = self.p, self.W
        self.text(8, 56, "REGULATORY DOMAIN", AMBER, 1)
        for i, d in enumerate(DOMAINS[:5]):
            color = MAGENTA if d == st.get("domain") else GRAY
            self.text(10 + i * 92, 72, d, color, 1)
        self.text(8, 96, "AIR RATE", AMBER, 1)
        for i, r in enumerate(RATES):
            color = MAGENTA if r == st.get("rate") else GRAY
            self.text(10 + i * 70, 112, r, color, 1)
        dom = fhss.DOMAINS.get(st.get("domain", "FCC915"), fhss.DOMAINS["FCC915"])
        cap = st.get("capture") or {}
        self.text(8, 138, f"Sync: {fhss.sync_frequency(dom)} Hz   "
                          f"ch={dom.sync_channel}/{dom.freq_count}", WHITE, 1)
        self.text(8, 154, f"Radio: {st.get('radio', 'none')}   "
                          f"sync word: {st.get('sync_word', '-')}", WHITE, 1)
        if st.get("radio") == "none":
            self.text(8, 174, "NO RADIO: stop meshtasticd; ch341 spidev required", RED, 1)

    def draw_scan(self):
        st = self.state or {}
        cap = st.get("capture") or {}
        p, W = self.p, self.W
        p.fill_rect(12, 54, W - 24, 108, PANEL)
        p.rect(12, 54, W - 24, 108, GRID)
        self.text(24, 60, "SYNC PACKET CAPTURE", MAGENTA, 2)
        self.text(24, 82, f"raw LoRa packets: {cap.get('raw_packets', 0)}", WHITE, 1)
        self.text(24, 98, f"CRC-valid ELRS sync: {cap.get('valid_sync_packets', 0)}",
                  GREEN if cap.get("valid_sync_packets") else AMBER, 2)
        tail = cap.get("last_uid_tail")
        self.text(24, 122, "UID4/5: " + (bytes(tail).hex() if tail else "--"), WHITE, 1)
        self.text(24, 138, f"sync channel: {cap.get('sync_channel_hz', 0)} Hz", GRAY, 1)

    def draw_track(self):
        st = self.state or {}
        cap = st.get("capture") or {}
        p, W = self.p, self.W
        p.fill_rect(12, 54, W - 24, 108, PANEL)
        p.rect(12, 54, W - 24, 108, GRID)
        self.text(24, 60, "HOP TIMING CAPTURE", MAGENTA, 2)
        self.text(24, 84, "Park on one channel and record the", GRAY, 1)
        self.text(24, 99, "packet offsets from the last sync.", GRAY, 1)
        self.text(24, 122, f"channel observations: {cap.get('channel_observations', 0)}",
                  GREEN if cap.get("channel_observations") else AMBER, 2)
        self.text(24, 146, "Needs a CRC-valid sync packet from SCAN first.", GRAY, 1)

    def draw_uid(self):
        st = self.state or {}
        rec = st.get("recovery") or {}
        phr = st.get("phrase") or {}
        p, W = self.p, self.W
        self.text(8, 56, "FHSS SEED RECOVERY", AMBER, 2)
        self.text(10, 76, f"observations: {rec.get('observations', 0)}", GRAY, 1)
        self.text(10, 92, f"candidates: {rec.get('candidates', 0)}", GRAY, 1)
        uid = rec.get("uid")
        self.text(10, 110, f"UID: {uid or '--'}", GREEN if uid else AMBER, 2)
        candidates = rec.get("candidate_uids") or []
        for i, c in enumerate(candidates[:4]):
            self.text(10, 130 + i * 13, f"  [{i}] {c}", GRAY, 1)
        self.text(10, 174, f"phrase: {phr.get('value') or '--'} "
                           f"({'confirmed' if phr.get('confirmed') else 'unconfirmed'})",
                  GREEN if phr.get("confirmed") else AMBER, 1)

    def draw_probe(self):
        st = self.state or {}
        probe = st.get("probe") or {}
        p, W = self.p, self.W
        p.fill_rect(12, 56, W - 24, 112, PANEL)
        p.rect(12, 56, W - 24, 112, GRID)
        self.text(24, 64, "AUTHORIZED BENCH LINK PROBE", MAGENTA, 2)
        self.text(24, 88, "Sends a sync packet only. No channel or", GRAY, 1)
        self.text(24, 103, "control data is generated (no actuator).", GRAY, 1)
        status = "CONFIRMED" if probe.get("confirmed") else (
            "SENT / UNCONFIRMED" if probe.get("sent") else "NOT RUN")
        color = GREEN if probe.get("confirmed") else AMBER
        self.text(24, 128, f"result: {status}", color, 2)
        self.text(24, 150, str(probe.get("detail", ""))[:60], GRAY, 1)

    def draw_log(self):
        logs = (self.state or {}).get("logs") or []
        for i, line in enumerate(logs[-9:]):
            self.text(8, 56 + i * 14, str(line)[:77], GRAY, 1)

    def render(self):
        p = self.p
        p.clear(BLACK)
        if self.state is None:
            p.fill_rect(0, 90, self.W, 40, PANEL)
            self.text(self.W // 2 - 90, 102, "Waiting for engine...", CYAN, 2)
        else:
            self.header()
            if self.screen == "INTRO": self.draw_intro()
            elif self.screen == "RADIO": self.draw_radio()
            elif self.screen == "SCAN": self.draw_scan()
            elif self.screen == "TRACK": self.draw_track()
            elif self.screen == "UID": self.draw_uid()
            elif self.screen == "PROBE": self.draw_probe()
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
            if self.screen == "RADIO":
                idx = DOMAINS.index(st.get("domain", "FCC915")) if st.get("domain") in DOMAINS else 0
                send_cmd({"cmd": "domain", "value": DOMAINS[(idx - 1) % len(DOMAINS)]})
        elif btn == self.p.BTN_DOWN:
            if self.screen == "RADIO":
                idx = DOMAINS.index(st.get("domain", "FCC915")) if st.get("domain") in DOMAINS else 0
                send_cmd({"cmd": "domain", "value": DOMAINS[(idx + 1) % len(DOMAINS)]})
        elif btn == self.p.BTN_A:
            if self.screen == "INTRO":
                if not st.get("authorized"):
                    send_cmd({"cmd": "authorize"})
                else:
                    self.screen_idx = 1
            elif self.screen == "SCAN":
                send_cmd({"cmd": "capture", "seconds": 10})
            elif self.screen == "TRACK":
                send_cmd({"cmd": "track", "seconds": 20})
            elif self.screen == "UID":
                send_cmd({"cmd": "recover"})
            elif self.screen == "PROBE":
                send_cmd({"cmd": "probe"})
        elif btn == self.p.BTN_B:
            if self.screen == "RADIO":
                cur = st.get("rate", "100Hz")
                idx = RATES.index(cur) if cur in RATES else 1
                send_cmd({"cmd": "rate", "value": RATES[(idx + 1) % len(RATES)]})
            elif self.screen == "SCAN":
                cur = st.get("sync_word", "0x1212")
                words = ["0x1212", "0x1424", "0x3444", "0x0000"]
                idx = words.index(cur) if cur in words else 0
                send_cmd({"cmd": "syncword", "value": words[(idx + 1) % len(words)]})
            elif self.screen == "UID":
                send_cmd({"cmd": "crack"})
            else:
                self.screen_idx = 0

    def run(self):
        while True:
            st = load_state()
            if st is not None:
                self.state = st
            ev = self.p.get_input_event()
            if ev is not None and getattr(ev, "type", 1) in (1, self.p.EVENT_PRESS):
                self.button(int(getattr(ev, "button", 0)))
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
        ui = ElrsJackUI(pager)
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
