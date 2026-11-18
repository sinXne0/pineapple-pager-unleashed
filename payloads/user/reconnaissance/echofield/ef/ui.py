#!/usr/bin/env python3
"""ECHOFIELD on-device UI (480x222).

Screens: SCOPE -> CONTACTS -> SETUP -> LOG.

The UI never touches the HackRF.  It reads /tmp/echofield_state.json and
appends commands to /tmp/echofield_cmd.jsonl.  The engine owns the SDR.

Dev machine:
    python3 ef/ui.py --headless --sample --frames 3
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

from ef import radar  # noqa: E402

STATE = os.environ.get("ECHOFIELD_STATE", "/tmp/echofield_state.json")
CMD = os.environ.get("ECHOFIELD_CMD", "/tmp/echofield_cmd.jsonl")


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
DARK = rgb(0, 10, 12)
PANEL = rgb(0, 24, 24)
GRID = rgb(0, 58, 56)
SEL = rgb(0, 76, 68)
DIM = rgb(0, 96, 88)

SCREENS = ["SCOPE", "CONTACTS", "SETUP", "LOG"]


class FakePager:
    BTN_UP = 0x01
    BTN_DOWN = 0x02
    BTN_LEFT = 0x04
    BTN_RIGHT = 0x08
    BTN_A = 0x10
    BTN_B = 0x20
    BTN_POWER = 0x40
    EVENT_PRESS = 1
    EVENT_RELEASE = 2

    def __init__(self, width=480, height=222):
        self.width = width
        self.height = height
        self.calls = 0
        self.frames = 0
        self.events = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def _n(self, *a, **k):
        self.calls += 1

    def init(self): self._n()
    def cleanup(self): self._n()
    def set_rotation(self, r): self._n()
    def clear(self, c=0): self._n()
    def flip(self): self.frames += 1
    def delay(self, ms): pass
    def get_ticks(self): return int(time.time() * 1000)
    def frame_sync(self): return 0
    def get_input_event(self):
        if not self.events:
            return None
        ev = self.events.pop(0)
        if isinstance(ev, tuple):
            class E: pass
            e = E()
            e.button, e.type = ev
            return e
        return ev
    def peek_buttons(self): return 0
    def clear_input_events(self): self._n()
    def fill_rect(self, *a): self._n()
    def rect(self, *a): self._n()
    def hline(self, *a): self._n()
    def vline(self, *a): self._n()
    def line(self, *a): self._n()
    def circle(self, *a): self._n()
    def fill_circle(self, *a): self._n()
    def pixel(self, *a): self._n()
    def draw_text(self, *a): self._n()
    def draw_text_centered(self, *a): self._n()
    def text_width(self, text, size=1): return len(str(text)) * 6 * size
    def play_rtttl(self, *a, **k): self._n()
    def stop_audio(self): self._n()
    def vibrate(self, ms=200): self._n()
    def led_rgb(self, *a): self._n()
    def led_dpad(self, *a): self._n()
    def led_all_off(self): self._n()
    def set_brightness(self, p): return 0


def load_state(path=None):
    try:
        with open(path or STATE, "r") as fh:
            obj = json.load(fh)
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def send_cmd(obj, path=None):
    try:
        with open(path or CMD, "a") as fh:
            fh.write(json.dumps(obj, separators=(",", ":")) + "\n")
        return True
    except Exception:
        return False


def sample_state():
    t = time.time()
    caf = radar.simulate_frame(t, rows=18, cols=24)
    contacts = radar.simulate_contacts(t, sample_rate_hz=2000000, rows=18, cols=24)
    return {
        "phase": "capture", "running": True, "mode": "sim",
        "station": "FM 100.1", "freq_mhz": 100.1, "sample_rate": 2000000,
        "gain": 24, "caf": caf, "contacts": contacts,
        "logs": ["ECHOFIELD ready", "capture started (sim)",
                 "reference: FM 100.1 MHz", "peak: E01 24.6 dB"],
        "stats": {"frames": 42, "contacts": len(contacts),
                  "range_res_km": 0.075, "doppler_span": 250},
        "error": "",
    }


class EchoFieldUI:
    FPS_DELAY_MS = 80

    def __init__(self, pager):
        self.p = pager
        self.W = pager.width
        self.H = pager.height
        self.state = None
        self.screen_idx = 0
        self.sel = 0
        self.last_sent = 0.0
        self.done = False

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
        p.fill_rect(0, 0, W, 26, DARK)
        p.hline(0, 26, W, DIM)
        self.text(6, 6, "ECHOFIELD", GREEN, 2)
        st = self.state or {}
        mode = str(st.get("mode", "sim")).upper()
        station = st.get("station", "FM --")
        self.text(150, 8, "%s / %s" % (mode, station), CYAN, 1)
        run = bool(st.get("running"))
        color = GREEN if run else (RED if st.get("error") else GRAY)
        p.fill_circle(W - 16, 13, 5, color)
        p.rect(W - 16, 13, 5, color)
        tabs = ["SCAN", "CONT", "SET", "LOG"]
        x = W - 210
        for i, tab in enumerate(tabs):
            c = AMBER if i == self.screen_idx else GRAY
            self.text(x, 8, tab, c, 1)
            x += 48

    def footer(self):
        p, W, H = self.p, self.W, self.H
        p.fill_rect(0, H - 22, W, 22, DARK)
        p.hline(0, H - 22, W, DIM)
        if self.screen == "SCOPE":
            self.text(6, H - 17, "L/R screens  A start/stop", GRAY, 1)
        elif self.screen == "CONTACTS":
            self.text(6, H - 17, "U/D select  A ack  L/R screens", GRAY, 1)
        elif self.screen == "SETUP":
            self.text(6, H - 17, "U/D value  L/R field  A toggle", GRAY, 1)
        else:
            self.text(6, H - 17, "L/R screens", GRAY, 1)
        err = (self.state or {}).get("error")
        if err:
            self.text(W - 190, H - 17, str(err)[:28], RED, 1)

    def draw_scope(self):
        p = self.p
        st = self.state or {}
        caf = st.get("caf") or []
        x0, y0, cw, ch = 46, 36, self.W - 62, 144
        p.fill_rect(x0, y0, cw, ch, PANEL)
        p.rect(x0, y0, cw, ch, GRID)
        rows, cols = len(caf), len(caf[0]) if caf else 0
        if rows and cols:
            cw_cell = cw / float(cols)
            ch_cell = ch / float(rows)
            for r in range(rows):
                for c in range(cols):
                    v = max(0.0, min(1.0, float(caf[r][c])))
                    if v < 0.18:
                        continue
                    color = DARK if v < 0.35 else (DIM if v < 0.6 else (CYAN if v < 0.82 else AMBER))
                    p.fill_rect(int(x0 + c * cw_cell), int(y0 + r * ch_cell),
                                int(cw_cell) + 1, int(ch_cell) + 1, color)
        for i in range(1, 5):
            y = y0 + ch * i // 5
            p.hline(x0, int(y), cw, GRID)
        for i in range(1, 6):
            x = x0 + cw * i // 6
            p.vline(int(x), y0, ch, GRID)
        max_range = radar.lag_to_range_km(max(1, rows) * 256,
                                          int(st.get("sample_rate", 2000000)))
        for i in range(6):
            label = "%.0f" % (max_range * i / 5.0)
            self.text(8, y0 + ch * i // 5 - 4, label, GRAY, 1)
        self.text(8, y0 - 12, "km", CYAN, 1)
        self.text(x0, y0 + ch + 4, "-250", GRAY, 1)
        self.text(x0 + cw // 2 - 10, y0 + ch + 4, "0", GRAY, 1)
        self.text(x0 + cw - 28, y0 + ch + 4, "+250 Hz", GRAY, 1)
        stats = st.get("stats") or {}
        self.text(x0, y0 + ch + 16,
                  "frames %s  res %.0fm  peaks %s" %
                  (stats.get("frames", 0),
                   float(stats.get("range_res_km", 0)) * 1000,
                   len(st.get("contacts") or [])), GREEN, 1)

    def draw_contacts(self):
        p, W = self.p, self.W
        contacts = (self.state or {}).get("contacts") or []
        self.text(8, 34, "ID   RANGE    VEL     SNR", AMBER, 1)
        p.hline(6, 48, W - 12, GRID)
        if not contacts:
            self.text(12, 70, "No contacts", GRAY, 2)
            self.text(12, 96, "Point the reference antenna at a strong", GRAY, 1)
            self.text(12, 110, "FM transmitter and start capture.", GRAY, 1)
            return
        for i, c in enumerate(contacts[:8]):
            y = 54 + i * 16
            if i == self.sel:
                p.fill_rect(4, y - 2, W - 8, 15, SEL)
            color = WHITE if i == self.sel else GRAY
            line = "%-4s %7.2fkm %+6.1fm/s %5.1fdB" % (
                c.get("id", "?"), float(c.get("range_km", 0)),
                float(c.get("velocity_ms", 0)), float(c.get("snr", 0)))
            self.text(10, y, line, color, 1)

    def draw_setup(self):
        p, W = self.p, self.W
        st = self.state or {}
        fields = [
            ("MODE", str(st.get("mode", "sim"))),
            ("FREQ", "%.1f MHz" % float(st.get("freq_mhz", 100.1))),
            ("GAIN", "%s" % st.get("gain", 24)),
            ("RATE", "%s Ms/s" % (float(st.get("sample_rate", 2000000)) / 1e6)),
        ]
        for i, (k, v) in enumerate(fields):
            y = 42 + i * 28
            color = AMBER if i == self.field else WHITE
            self.text(12, y, k, color, 2)
            self.text(150, y, v, color, 2)
        self.text(12, 168, "A toggles capture", GREEN, 1)
        self.text(170, 168, "B back to scope", GRAY, 1)

    def draw_log(self):
        p = self.p
        logs = (self.state or {}).get("logs") or []
        for i, line in enumerate(logs[-9:]):
            self.text(8, 38 + i * 15, str(line)[:76], GRAY, 1)

    @property
    def field(self):
        return getattr(self, "_field", 0)

    @field.setter
    def field(self, value):
        self._field = value % 4

    def render(self):
        p = self.p
        p.clear(BLACK)
        st = self.state
        if st is None:
            p.fill_rect(0, 80, self.W, 40, PANEL)
            self.text(self.W // 2 - 70, 92, "Waiting for engine...", CYAN, 2)
        else:
            self.header()
            if self.screen == "SCOPE":
                self.draw_scope()
            elif self.screen == "CONTACTS":
                self.draw_contacts()
            elif self.screen == "SETUP":
                self.draw_setup()
            else:
                self.draw_log()
            self.footer()
        p.flip()

    def button(self, btn):
        now = time.time()
        if now - self.last_sent < 0.12:
            return
        self.last_sent = now
        if btn == self.p.BTN_LEFT:
            self.screen_idx = (self.screen_idx - 1) % len(SCREENS)
        elif btn == self.p.BTN_RIGHT:
            self.screen_idx = (self.screen_idx + 1) % len(SCREENS)
        elif btn == self.p.BTN_UP:
            if self.screen == "CONTACTS":
                self.sel = max(0, self.sel - 1)
            elif self.screen == "SETUP":
                self.field = self.field - 1
        elif btn == self.p.BTN_DOWN:
            if self.screen == "CONTACTS":
                self.sel += 1
            elif self.screen == "SETUP":
                self.field = self.field + 1
        elif btn == self.p.BTN_A:
            if self.screen == "CONTACTS":
                contacts = (self.state or {}).get("contacts") or []
                if contacts and self.sel < len(contacts):
                    send_cmd({"cmd": "ack", "id": contacts[self.sel].get("id", "")})
            else:
                running = bool((self.state or {}).get("running"))
                send_cmd({"cmd": "stop" if running else "start"})
        elif btn == self.p.BTN_B:
            self.screen_idx = 0

    def run(self):
        while not self.done:
            st = load_state()
            if st is not None:
                self.state = st
                if st.get("phase") == "off":
                    self.done = True
                    break
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

    if args.headless:
        pager = FakePager()
    else:
        from pagerctl import Pager
        pager = Pager()
    with pager:
        pager.init()
        pager.set_rotation(270)
        ui = EchoFieldUI(pager)
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
