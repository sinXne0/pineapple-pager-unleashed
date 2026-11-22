#!/usr/bin/env python3
"""NULLGATE on-device UI (480x222).

Screens: INTRO -> TARGETS -> PROBE -> EXPLOIT -> LOOT.

Reads /tmp/nullgate_state.json and appends commands to /tmp/nullgate_cmd.jsonl.
Never touches the target itself. Every status shown comes from engine state,
which is only ever set from a real HTTP response or a real callback.

Dev machine:
    python3 sd/ui.py --headless --sample --frames 5
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

STATE = os.environ.get("NULLGATE_STATE", "/tmp/nullgate_state.json")
CMD = os.environ.get("NULLGATE_CMD", "/tmp/nullgate_cmd.jsonl")


def rgb(r, g, b):
    return ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)


BLACK = 0x0000
WHITE = 0xFFFF
RED = rgb(255, 70, 70)
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

SCREENS = ["INTRO", "TARGETS", "PROBE", "EXPLOIT", "LOOT"]
TABS = ["AUTH", "TGT", "PROBE", "OWN", "LOOT"]
STAGES = ["proof", "loot", "persist"]

VERDICT_COLOR = {
    "vulnerable": GREEN, "patched": RED, "inconclusive": AMBER,
    "unaffected": GRAY, "error": RED, "none": GRAY,
}


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
        with open(path or os.environ.get("NULLGATE_CMD", CMD), "a") as fh:
            fh.write(json.dumps(obj, separators=(",", ":")) + "\n")
        return True
    except Exception:
        return False


def sample_state():
    return {
        "authorized": True,
        "phase": "loot",
        "targets": discovery.sample_targets(),
        "target_index": 0,
        "selected": discovery.sample_targets()[0],
        "probe": {"state": "vulnerable", "checked": True,
                  "detail": "auth bypass reached the vulnerable handler",
                  "http_status": 200},
        "stage": "loot",
        "exploit": {"proof": "confirmed", "loot": "confirmed",
                    "persist": "unconfirmed"},
        "nonce": "a1b2c3d4e5f6",
        "callback": {"host": "172.16.52.1", "port": 8844, "active": True},
        "token": "",
        "loot_files": ["/root/loot/nullgate/dump_a1b2c3d4e5f6.tgz"],
        "read_result": {"path": "/etc/passwd", "ok": True,
                        "text": "root:x:0:0:root:/root:/bin/bash\n"},
        "logs": ["NULLGATE ready", "authorization accepted",
                 "discovered 3 hosts (1 vulnerable)",
                 "selected 192.168.1.10:11443",
                 "probe: vulnerable - bypass reached handler",
                 "proof CONFIRMED via callback",
                 "loot CONFIRMED via callback"],
        "error": "",
        "stats": {"targets": 3, "vulnerable": 1, "confirmed": 2},
    }


class NullgateUI:
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
        self.text(6, 6, "NULLGATE", MAGENTA, 2)
        st = self.state or {}
        phase = str(st.get("phase", "idle")).upper()
        self.text(92, 8, "UNIFI OS ROOT CHAIN / %s" % phase, CYAN, 1)
        err = st.get("error")
        confirmed = sum(1 for v in (st.get("exploit") or {}).values()
                        if v == "confirmed")
        led = RED if err else (GREEN if confirmed else
                               (AMBER if st.get("authorized") else GRAY))
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
            "TARGETS": "U/D select  A discover/choose",
            "PROBE": "A run safe probe  B targets",
            "EXPLOIT": "U/D stage  A execute  B back",
            "LOOT": "A read file  B back",
        }
        self.text(6, H - 17, hints.get(self.screen, ""), GRAY, 1)
        err = (self.state or {}).get("error")
        if err:
            self.text(W - 210, H - 17, str(err)[:34], RED, 1)

    def draw_intro(self):
        p, W = self.p, self.W
        st = self.state or {}
        p.fill_rect(12, 38, W - 24, 132, PANEL)
        p.rect(12, 38, W - 24, 132, GRID)
        self.text(22, 46, "NULLGATE // UNIFI OS ROOT CHAIN", MAGENTA, 2)
        lines = [
            "One request -> auth bypass -> command injection.",
            "Root via passwordless sudo -> secret store ->",
            "forged owner sessions that survive the patch.",
            "",
            "CVE-2026-34908/34909/34910  (CVSS 10.0, KEV)",
            "Target: UniFi OS Server <=5.0.6 / hw <=5.1.11",
            "Needs L3 access to TCP 11443 on the console.",
            "",
            "AUTHORIZED TESTING ONLY.",
        ]
        for i, line in enumerate(lines):
            color = AMBER if "AUTHORIZED" in line else GRAY
            self.text(22, 66 + i * 11, line, color, 1)
        auth = bool(st.get("authorized"))
        label = ("AUTHORIZED - press A to continue" if auth else
                 "NOT AUTHORIZED - press A to authorize")
        self.text(22, 158, label, GREEN if auth else RED, 2)

    def draw_targets(self):
        p, W = self.p, self.W
        st = self.state or {}
        targets = st.get("targets") or []
        self.text(8, 34, "HOST             PORT  VERDICT     DETAIL", AMBER, 1)
        p.hline(6, 48, W - 12, GRID)
        if not targets:
            self.text(12, 70, "No targets yet", GRAY, 2)
            self.text(12, 96, "Press A to sweep the local subnet for :11443", GRAY, 1)
            return
        for i, t in enumerate(targets[:8]):
            y = 54 + i * 16
            if i == self.sel:
                p.fill_rect(4, y - 2, W - 8, 15, SEL)
            color = WHITE if i == self.sel else GRAY
            state = str(t.get("state", "?"))
            self.text(10, y, "%-16s %5s  %-11s" %
                      (str(t.get("host", "?"))[:16], t.get("port", "?"),
                       state[:11]), color, 1)
            self.text(W - 168, y, str(t.get("detail", ""))[:26], GRAY, 1)

    def draw_probe(self):
        p, W = self.p, self.W
        st = self.state or {}
        target = st.get("selected") or {}
        probe = st.get("probe") or {}
        self.text(8, 34, "SELECTED CONSOLE", AMBER, 2)
        p.hline(6, 52, W - 12, GRID)
        self.text(10, 58, "HOST: %s:%s" % (target.get("host", "--"),
                                          target.get("port", "--")), WHITE, 1)
        self.text(10, 74, "TLS: %s   FINGERPRINT: %s" %
                  (target.get("tls"), target.get("fingerprint")), GRAY, 1)
        state = probe.get("state", "none")
        self.text(10, 98, "SAFE PROBE: %s" % state.upper(),
                  VERDICT_COLOR.get(state, GRAY), 2)
        self.text(10, 118, str(probe.get("detail", "not run"))[:62], GRAY, 1)
        if probe.get("checked") and state == "vulnerable":
            self.text(10, 140, "No command executed during the probe.", GREEN, 1)
            self.text(10, 156, "Press A on OWN to run the chain.", GREEN, 1)

    def draw_exploit(self):
        p, W = self.p, self.W
        st = self.state or {}
        ex = st.get("exploit") or {}
        self.text(8, 34, "EXPLOIT CHAIN", AMBER, 2)
        p.hline(6, 52, W - 12, GRID)
        labels = [("proof", "1 PROOF  - rce + callback"),
                  ("loot", "2 LOOT   - sudo chmod + secrets"),
                  ("persist", "3 PERSIST- forged owner token")]
        for i, (key, label) in enumerate(labels):
            y = 60 + i * 22
            if key == st.get("stage"):
                p.fill_rect(4, y - 2, W - 8, 19, SEL)
            status = ex.get(key, "none")
            color = (GREEN if status == "confirmed" else
                     RED if status == "unconfirmed" else
                     AMBER if status == "sent" else GRAY)
            self.text(10, y, label, WHITE if key == st.get("stage") else GRAY, 1)
            self.text(W - 110, y, status.upper(), color, 1)
        self.text(10, 140, "confirmed = target called back with nonce", DIM, 1)
        self.text(10, 156, "HTTP 200 alone is NOT claimed as success.", DIM, 1)

    def draw_loot(self):
        p = self.p
        st = self.state or {}
        files = st.get("loot_files") or []
        rr = st.get("read_result") or {}
        self.text(8, 34, "LOOT", AMBER, 2)
        p.hline(6, 52, self.W - 12, GRID)
        self.text(10, 58, "collected dumps: %d" % len(files), WHITE, 1)
        for i, f in enumerate(files[-3:]):
            self.text(14, 74 + i * 14, str(f)[:64], GRAY, 1)
        if rr:
            self.text(10, 124, "LAST READ: %s (%s)" %
                      (rr.get("path", "?"), "ok" if rr.get("ok") else "failed"),
                      GREEN if rr.get("ok") else RED, 1)
            text = str(rr.get("text", ""))[:70].replace("\n", " ")
            self.text(10, 140, text, DIM, 1)
        if st.get("token"):
            self.text(10, 162, "forged owner token ready", GREEN, 1)

    def render(self):
        p = self.p
        p.clear(BLACK)
        st = self.state
        if st is None:
            p.fill_rect(0, 80, self.W, 40, PANEL)
            self.text(self.W // 2 - 90, 92, "Waiting for engine...", CYAN, 2)
        else:
            self.header()
            if self.screen == "INTRO":
                self.draw_intro()
            elif self.screen == "TARGETS":
                self.draw_targets()
            elif self.screen == "PROBE":
                self.draw_probe()
            elif self.screen == "EXPLOIT":
                self.draw_exploit()
            else:
                self.draw_loot()
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
            elif self.screen == "EXPLOIT":
                idx = STAGES.index(st.get("stage", "proof")) if st.get("stage") in STAGES else 0
                send_cmd({"cmd": "stage", "mode": STAGES[(idx - 1) % len(STAGES)]})
        elif btn == self.p.BTN_DOWN:
            if self.screen == "TARGETS":
                self.sel += 1
            elif self.screen == "EXPLOIT":
                idx = STAGES.index(st.get("stage", "proof")) if st.get("stage") in STAGES else 0
                send_cmd({"cmd": "stage", "mode": STAGES[(idx + 1) % len(STAGES)]})
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
            elif self.screen == "PROBE":
                send_cmd({"cmd": "probe"})
            elif self.screen == "EXPLOIT":
                send_cmd({"cmd": "exploit", "stage": st.get("stage", "proof")})
            elif self.screen == "LOOT":
                send_cmd({"cmd": "read", "path": "/etc/passwd"})
        elif btn == self.p.BTN_B:
            if self.screen in ("PROBE", "EXPLOIT", "LOOT"):
                self.screen_idx = max(0, self.screen_idx - 1)
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
        ui = NullgateUI(pager)
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
