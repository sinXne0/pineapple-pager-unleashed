#!/usr/bin/env python3
"""SHARD on-device UI (480x222).

Screens: INTRO -> TARGETS -> PLAN -> INJECT -> LOG.

The UI never touches the radio. It reads /tmp/shard_state.json and appends
commands to /tmp/shard_cmd.jsonl; the engine owns the hardware.

Dev machine:
    python3 sd/ui.py --headless --sample --frames 4
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

from sd import discovery  # noqa: E402

STATE = os.environ.get("SHARD_STATE", "/tmp/shard_state.json")
CMD = os.environ.get("SHARD_CMD", "/tmp/shard_cmd.jsonl")


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

SCREENS = ["INTRO", "TARGETS", "PLAN", "INJECT", "LOG"]
TABS = ["AUTH", "TGT", "PLAN", "FRG", "LOG"]
ATTACKS = ["amsdu", "dns", "icmp"]


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
        with open(path or os.environ.get("SHARD_CMD", CMD), "a") as fh:
            fh.write(json.dumps(obj, separators=(",", ":")) + "\n")
        return True
    except Exception:
        return False


def sample_state():
    return {
        "authorized": True,
        "phase": "plan",
        "iface": "wlan1mon",
        "targets": discovery.sample_targets(),
        "target_index": 0,
        "selected": discovery.sample_targets()[0],
        "probe": {"os_ok": True, "air_ok": True, "checked": True,
                  "detail": "aireplay-ng 30/30", "monitor": True},
        "attack": "amsdu",
        "inject_count": 3,
        "verified": True,
        "logs": ["SHARD ready", "authorization accepted",
                 "discovered 3 targets (2 injectable)",
                 "selected 00:11:22:33:44:55 ch6",
                 "probe os=True air=True",
                 "injected 92 bytes to aa:bb:cc:dd:ee:01 on ch6",
                 "verify: 2 frames observed"],
        "error": "",
        "stats": {"injected": 3, "targets": 3, "injectable": 2},
    }


class ShardUI:
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
        self.text(6, 6, "SHARD", MAGENTA, 2)
        st = self.state or {}
        phase = str(st.get("phase", "idle")).upper()
        self.text(80, 8, "FRAGATTACK INJECTOR / %s" % phase, CYAN, 1)
        err = st.get("error")
        led = RED if err else (GREEN if st.get("verified") else
                               (AMBER if st.get("inject_count") else GRAY))
        p.fill_circle(W - 16, 13, 5, led)
        p.rect(W - 16, 13, 5, led)
        x = W - 214
        for i, tab in enumerate(TABS):
            color = MAGENTA if i == self.screen_idx else GRAY
            self.text(x, 8, tab, color, 1)
            x += 40

    def footer(self):
        p, W, H = self.p, self.W, self.H
        p.fill_rect(0, H - 22, W, 22, DARK)
        p.hline(0, H - 22, W, DIM)
        hints = {
            "INTRO": "A authorize  L/R screens",
            "TARGETS": "U/D select  A choose  A discover",
            "PLAN": "L/R mode  A probe  B targets",
            "INJECT": "A inject fragment  B verify  L/R screens",
            "LOG": "L/R screens",
        }
        self.text(6, H - 17, hints.get(self.screen, ""), GRAY, 1)
        err = (self.state or {}).get("error")
        if err:
            self.text(W - 200, H - 17, str(err)[:30], RED, 1)

    def draw_intro(self):
        p, W = self.p, self.W
        st = self.state or {}
        p.fill_rect(12, 38, W - 24, 132, PANEL)
        p.rect(12, 38, W - 24, 132, GRID)
        self.text(22, 46, "SHARD // 802.11 FRAGMENT INJECTION", MAGENTA, 2)
        lines = [
            "Injects an A-MSDU frame into a WPA2 client",
            "without the PSK (CVE-2020-24588).",
            "",
            "Hardware: WiFi Pineapple Pager (wlan1mon)",
            "Limits: 2.4GHz / non-DFS 5GHz, no WPA3/PMF",
            "",
            "AUTHORIZED TESTING ONLY.",
        ]
        for i, line in enumerate(lines):
            color = AMBER if "AUTHORIZED" in line else GRAY
            self.text(22, 70 + i * 12, line, color, 1)
        auth = bool(st.get("authorized"))
        color = GREEN if auth else RED
        label = "AUTHORIZED - press A to continue" if auth else "NOT AUTHORIZED - press A to authorize"
        self.text(22, 156, label, color, 2)

    def draw_targets(self):
        p, W = self.p, self.W
        st = self.state or {}
        targets = st.get("targets") or []
        self.text(8, 34, "BSSID             CH  CLIENT           STATUS", AMBER, 1)
        p.hline(6, 48, W - 12, GRID)
        if not targets:
            self.text(12, 70, "No targets yet", GRAY, 2)
            self.text(12, 96, "Press A to discover from recon data", GRAY, 1)
            self.text(12, 110, "(or sniff data frames on wlan1mon)", GRAY, 1)
            return
        for i, t in enumerate(targets[:8]):
            y = 54 + i * 16
            if i == self.sel:
                p.fill_rect(4, y - 2, W - 8, 15, SEL)
            color = WHITE if i == self.sel else GRAY
            status = "OK" if t.get("injectable") else "BLOCKED"
            scolor = GREEN if t.get("injectable") else RED
            line = "%-17s %2s  %-17s" % (
                str(t.get("bssid", "?"))[:17], t.get("channel", "?"),
                str(t.get("client", "?"))[:17])
            self.text(10, y, line, color, 1)
            self.text(W - 70, y, status, scolor, 1)

    def draw_plan(self):
        p, W = self.p, self.W
        st = self.state or {}
        target = st.get("selected") or {}
        probe = st.get("probe") or {}
        self.text(8, 34, "SELECTED TARGET", AMBER, 2)
        p.hline(6, 52, W - 12, GRID)
        self.text(10, 58, "BSSID:  %s" % target.get("bssid", "--"), WHITE, 1)
        self.text(10, 72, "CLIENT: %s" % target.get("client", "--"), WHITE, 1)
        self.text(10, 86, "CHANNEL: %s   SSID: %s" %
                  (target.get("channel", "--"), str(target.get("ssid", ""))[:18]), GRAY, 1)
        ok, reason = discovery.is_injectable_target(target) if target else (False, "no target")
        self.text(10, 102, "TARGET: %s" % ("injectable" if ok else reason),
                  GREEN if ok else RED, 1)

        self.text(8, 122, "ATTACK MODE", AMBER, 2)
        mode = st.get("attack", "amsdu")
        x = 10
        for i, a in enumerate(ATTACKS):
            color = MAGENTA if a == mode else GRAY
            self.text(x, 140, "[%s]" % a.upper(), color, 1)
            x += 92

        if probe.get("checked"):
            status = "os=%s air=%s" % (probe.get("os_ok"), probe.get("air_ok"))
            color = GREEN if probe.get("os_ok") and probe.get("air_ok") else AMBER
            self.text(10, 160, "CAPABILITY: %s" % status, color, 1)
            self.text(10, 174, str(probe.get("detail", ""))[:60], GRAY, 1)
        else:
            self.text(10, 160, "CAPABILITY: not tested (press A)", AMBER, 1)

    def draw_inject(self):
        p, W = self.p, self.W
        st = self.state or {}
        count = int(st.get("inject_count", 0))
        verified = bool(st.get("verified"))
        p.fill_rect(12, 38, W - 24, 100, PANEL)
        p.rect(12, 38, W - 24, 100, GRID)
        self.text(24, 46, "FRAGMENT INJECTION", MAGENTA, 2)
        self.text(24, 68, "injected frames: %d" % count, WHITE, 2)
        result = "VERIFIED" if verified else "UNVERIFIED"
        self.text(24, 94, "result: %s" % result, GREEN if verified else AMBER, 2)
        self.text(24, 120, "A inject    B verify/inspect", GRAY, 1)
        packets = st.get("packets") or []
        if packets:
            last = packets[-1]
            self.text(10, 150, "LAST FRAME", AMBER, 1)
            self.text(10, 164, "%s -> %s ch%s bytes=%s" %
                      (last.get("bssid", "?"), last.get("client", "?"),
                       last.get("channel", "?"), last.get("bytes", 0)), GRAY, 1)
            self.text(10, 178, last.get("frame_hex", "")[:64], DIM, 1)

    def draw_log(self):
        p = self.p
        logs = (self.state or {}).get("logs") or []
        for i, line in enumerate(logs[-9:]):
            self.text(8, 38 + i * 15, str(line)[:76], GRAY, 1)

    def render(self):
        p = self.p
        p.clear(BLACK)
        st = self.state
        if st is None:
            p.fill_rect(0, 80, self.W, 40, PANEL)
            self.text(self.W // 2 - 80, 92, "Waiting for engine...", CYAN, 2)
        else:
            self.header()
            if self.screen == "INTRO":
                self.draw_intro()
            elif self.screen == "TARGETS":
                self.draw_targets()
            elif self.screen == "PLAN":
                self.draw_plan()
            elif self.screen == "INJECT":
                self.draw_inject()
            else:
                self.draw_log()
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
            if self.screen == "TARGETS":
                self.sel = max(0, self.sel - 1)
            elif self.screen == "PLAN":
                idx = ATTACKS.index(st.get("attack", "amsdu")) if st.get("attack", "amsdu") in ATTACKS else 0
                send_cmd({"cmd": "attack", "mode": ATTACKS[(idx - 1) % len(ATTACKS)]})
        elif btn == self.p.BTN_DOWN:
            if self.screen == "TARGETS":
                self.sel += 1
            elif self.screen == "PLAN":
                idx = ATTACKS.index(st.get("attack", "amsdu")) if st.get("attack", "amsdu") in ATTACKS else 0
                send_cmd({"cmd": "attack", "mode": ATTACKS[(idx + 1) % len(ATTACKS)]})
        elif btn == self.p.BTN_A:
            if self.screen == "INTRO":
                if not st.get("authorized"):
                    send_cmd({"cmd": "authorize", "value": True})
                else:
                    self.screen_idx = 1
            elif self.screen == "TARGETS":
                if not st.get("targets"):
                    send_cmd({"cmd": "discover"})
                elif self.sel < len(st["targets"]):
                    send_cmd({"cmd": "select", "index": self.sel})
                    self.screen_idx = 2
            elif self.screen == "PLAN":
                send_cmd({"cmd": "probe"})
            elif self.screen == "INJECT":
                send_cmd({"cmd": "inject"})
        elif btn == self.p.BTN_B:
            if self.screen == "PLAN":
                self.screen_idx = 1
            elif self.screen == "INJECT":
                send_cmd({"cmd": "verify"})
            else:
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
        ui = ShardUI(pager)
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
