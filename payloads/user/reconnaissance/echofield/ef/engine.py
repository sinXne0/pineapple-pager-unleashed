#!/usr/bin/env python3
"""ECHOFIELD engine.

Owns capture, correlation, contact tracking and state publication.  The UI
only reads state and appends commands, so a crashed UI never leaves the SDR
running and a slow CAF never freezes the display.
"""

from __future__ import annotations

import json
import os
import tempfile
import time

from . import hackrf, radar

STATE = os.environ.get("ECHOFIELD_STATE", "/tmp/echofield_state.json")
CMD = os.environ.get("ECHOFIELD_CMD", "/tmp/echofield_cmd.jsonl")
LOOT = os.environ.get("ECHOFIELD_LOOT", "/root/loot/echofield")

RANGE_BINS = 18
DOPPLER_BINS = 24
DOPPLERS = list(range(-250, 251, 50))[:DOPPLER_BINS]


def default_state():
    return {
        "app": "ECHOFIELD",
        "version": "0.1.0",
        "phase": "idle",
        "mode": os.environ.get("ECHOFIELD_MODE", "sim"),
        "station": "FM 100.1",
        "freq_mhz": float(os.environ.get("ECHOFIELD_FREQ", "100.1")),
        "sample_rate": int(os.environ.get("ECHOFIELD_RATE", "2000000")),
        "gain": int(os.environ.get("ECHOFIELD_GAIN", "24")),
        "interval": float(os.environ.get("ECHOFIELD_INTERVAL", "1.5")),
        "running": False,
        "caf": [],
        "contacts": [],
        "logs": ["ECHOFIELD ready"],
        "stats": {"frames": 0, "contacts": 0, "range_res_km": 0.0,
                  "doppler_span": 250, "last_frame": 0.0},
        "error": "",
    }


def atomic_write(path, obj):
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".echofield-", dir=directory)
    try:
        with os.fdopen(fd, "w") as fh:
            json.dump(obj, fh, separators=(",", ":"), sort_keys=True)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def append_jsonl(path, obj):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "a") as fh:
        fh.write(json.dumps(obj, separators=(",", ":"), sort_keys=True) + "\n")


class Engine:
    def __init__(self, state_path=None, cmd_path=None, loot=None):
        self.state_path = state_path or STATE
        self.cmd_path = cmd_path or CMD
        self.loot = loot or LOOT
        self.state = default_state()
        self.next_id = 1
        self.last_frame = 0.0
        self.frame_no = 0

    def load_commands(self):
        cmds = []
        try:
            with open(self.cmd_path, "r") as fh:
                lines = fh.readlines()
            with open(self.cmd_path, "w") as fh:
                fh.truncate(0)
        except FileNotFoundError:
            return cmds
        for line in lines:
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    cmds.append(obj)
            except Exception:
                pass
        return cmds

    def log(self, text):
        self.state["logs"] = (self.state.get("logs") or [])[-29:] + [str(text)]

    def handle(self, cmd):
        action = str(cmd.get("cmd", "")).lower()
        if action == "start":
            if self.state["mode"] == "hackrf" and not hackrf.available():
                self.state["error"] = "HackRF capture helper unavailable"
                self.log(self.state["error"])
            else:
                self.state["running"] = True
                self.state["phase"] = "capture"
                self.state["error"] = ""
                self.log("capture started (%s)" % self.state["mode"])
        elif action == "stop":
            self.state["running"] = False
            self.state["phase"] = "idle"
            self.log("capture stopped")
        elif action == "mode":
            mode = str(cmd.get("mode", "sim")).lower()
            if mode in ("sim", "file", "hackrf"):
                self.state["mode"] = mode
                self.log("mode=%s" % mode)
        elif action == "freq":
            try:
                self.state["freq_mhz"] = float(cmd["mhz"])
                self.state["station"] = "FM %.1f" % self.state["freq_mhz"]
                self.log("tuned to %.1f MHz" % self.state["freq_mhz"])
            except Exception:
                self.state["error"] = "bad frequency"
        elif action == "gain":
            try:
                self.state["gain"] = int(cmd["gain"])
                self.log("gain=%s" % self.state["gain"])
            except Exception:
                self.state["error"] = "bad gain"
        elif action == "interval":
            try:
                self.state["interval"] = max(0.5, float(cmd["seconds"]))
            except Exception:
                self.state["error"] = "bad interval"
        elif action == "ack":
            ident = str(cmd.get("id", ""))
            self.state["contacts"] = [c for c in self.state.get("contacts", [])
                                      if c.get("id") != ident]
            self.log("ack %s" % ident)
        elif action == "shutdown":
            self.state["running"] = False
            self.state["phase"] = "off"
            self.log("shutdown")

    def frame(self):
        mode = self.state["mode"]
        if mode == "sim":
            t = time.time()
            matrix = radar.simulate_frame(t, rows=RANGE_BINS, cols=DOPPLER_BINS)
            contacts = radar.simulate_contacts(t, sample_rate_hz=self.state["sample_rate"],
                                               rows=RANGE_BINS, cols=DOPPLER_BINS)
        elif mode == "file":
            ref = os.environ.get("ECHOFIELD_REF", "/tmp/echofield_capture/ref.cs8")
            surv = os.environ.get("ECHOFIELD_SURV", "/tmp/echofield_capture/surv.cs8")
            matrix = radar.caf_from_files(ref, surv, self.state["sample_rate"],
                                          dopplers=DOPPLERS, max_lag=8192)
            contacts = self.contacts_from_matrix(matrix)
        elif mode == "hackrf":
            matrix = hackrf.capture_caf(
                freq_mhz=self.state["freq_mhz"],
                sample_rate_hz=self.state["sample_rate"],
                gain=self.state["gain"],
                dopplers=DOPPLERS,
                max_lag=8192,
            )
            contacts = self.contacts_from_matrix(matrix)
        else:
            raise RuntimeError("unknown mode: %s" % mode)
        return matrix, contacts

    def contacts_from_matrix(self, matrix):
        peaks = radar.find_peaks(matrix, min_snr=0.45, max_peaks=6)
        max_range = radar.lag_to_range_km(len(matrix) * 256, self.state["sample_rate"])
        out = []
        for r, c, snr in peaks:
            rng = max_range * (r + 0.5) / len(matrix)
            vel = -250.0 + 500.0 * (c + 0.5) / max(1, len(matrix[0]))
            out.append({"id": "E%02d" % self.next_id, "range_km": round(rng, 2),
                        "velocity_ms": round(vel, 1), "snr": round(snr * 30, 1),
                        "row": r, "col": c, "age": 0})
            self.next_id += 1
        return out

    def tick(self):
        now = time.time()
        if self.state["running"] and (now - self.last_frame) >= self.state["interval"]:
            try:
                matrix, contacts = self.frame()
                self.state["caf"] = [[round(v, 3) for v in row] for row in matrix]
                self.state["contacts"] = contacts
                self.frame_no += 1
                self.last_frame = now
                self.state["stats"] = {
                    "frames": self.frame_no,
                    "contacts": len(contacts),
                    "range_res_km": round(radar.range_resolution_km(self.state["sample_rate"]), 3),
                    "doppler_span": 250,
                    "last_frame": now,
                }
                self.state["error"] = ""
            except Exception as exc:
                self.state["running"] = False
                self.state["phase"] = "idle"
                self.state["error"] = str(exc)
                self.log("error: %s" % exc)
        atomic_write(self.state_path, self.state)

    def save_loot(self):
        if not self.state.get("contacts"):
            return
        append_jsonl(os.path.join(self.loot, "contacts.jsonl"), {
            "ts": time.time(),
            "station": self.state["station"],
            "contacts": self.state["contacts"],
        })

    def run_forever(self):
        stop = False
        while not stop:
            for cmd in self.load_commands():
                self.handle(cmd)
                if cmd.get("cmd") == "shutdown":
                    stop = True
            self.tick()
            time.sleep(0.1)
        atomic_write(self.state_path, self.state)
        self.save_loot()


def run_forever():
    Engine().run_forever()


def selftest():
    e = Engine("/tmp/echofield_selftest_state.json", "/tmp/echofield_selftest_cmd.jsonl")
    matrix, contacts = e.frame()
    print("matrix=%dx%d contacts=%d" % (len(matrix), len(matrix[0]), len(contacts)))
    print("range resolution: %.3f km" % radar.range_resolution_km(e.state["sample_rate"]))


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "selftest":
        selftest()
    else:
        run_forever()
