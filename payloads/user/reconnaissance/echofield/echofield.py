#!/usr/bin/env python3
"""ECHOFIELD entry point."""

from __future__ import annotations

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from ef.engine import run_forever, selftest  # noqa: E402


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "engine"
    if cmd == "selftest":
        selftest()
    elif cmd == "engine":
        run_forever()
    else:
        print("usage: echofield.py [engine|selftest]", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
