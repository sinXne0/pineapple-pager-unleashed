#!/usr/bin/env python3
"""Target discovery helpers for SHARD.

SHARD does not do its own wideband scanning -- the Pager's recon engine is
already doing that far better. This module reads the recon/DHCP state that
the Pager maintains and turns it into a short list of candidate WPA2 targets
with a known BSSID, client MAC and channel.

Fallback: a tcpdump capture on wlan1mon can be parsed for data frames when
the recon database is not available on a particular firmware build.
"""

from __future__ import annotations

import csv
import glob
import json
import os
import re
import shutil
import subprocess
import time

from . import frames

MAC_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b")
RECON_GLOBS = (
    "/root/loot/recon/*.csv",
    "/root/loot/recon/*.json",
    "/root/loot/recon/*.jsonl",
    "/mmc/root/loot/recon/*.csv",
    "/mmc/root/loot/recon/*.json",
    "/mmc/root/loot/recon/*.jsonl",
    "/root/loot/*.csv",
    "/root/loot/*.json",
)


def load_recon_devices(limit=200):
    """Best-effort parse of the Pager's recon logs into device dicts."""
    devices = []
    seen = set()
    paths = []
    for pattern in RECON_GLOBS:
        paths.extend(glob.glob(pattern))
    for path in sorted(paths)[-12:]:
        try:
            if path.endswith(".jsonl"):
                with open(path, errors="replace") as fh:
                    for line in fh:
                        obj = json.loads(line)
                        devices.extend(_flatten_recon(obj))
            elif path.endswith(".json"):
                with open(path, errors="replace") as fh:
                    obj = json.load(fh)
                    devices.extend(_flatten_recon(obj))
            else:
                with open(path, errors="replace", newline="") as fh:
                    for row in csv.reader(fh):
                        d = _row_to_device(row)
                        if d:
                            devices.append(d)
        except Exception:
            continue

    out = []
    for d in devices:
        mac = d.get("bssid") or d.get("mac") or ""
        try:
            mac = frames.mac_to_str(mac)
        except Exception:
            continue
        if mac in seen or mac.startswith("ff:ff"):
            continue
        seen.add(mac)
        out.append(d)
        if len(out) >= limit:
            break
    return out


def _flatten_recon(obj):
    if isinstance(obj, list):
        for item in obj:
            yield from _flatten_recon(item)
        return
    if not isinstance(obj, dict):
        return
    d = {}
    for key in ("bssid", "mac", "address", "addr"):
        if key in obj and obj[key]:
            d["bssid"] = obj[key]
            break
    for key in ("ssid", "essid", "network"):
        if key in obj and obj[key]:
            d["ssid"] = str(obj[key])
            break
    for key in ("channel", "chan", "ch"):
        if key in obj and obj[key]:
            try:
                d["channel"] = int(obj[key])
            except Exception:
                pass
            break
    for key in ("encryption", "security", "enc"):
        if key in obj and obj[key]:
            d["security"] = str(obj[key])
            break
    if d.get("bssid"):
        yield d
    for nested in ("devices", "access_points", "aps", "clients", "results"):
        if nested in obj:
            yield from _flatten_recon(obj[nested])


def _row_to_device(row):
    if not row:
        return None
    d = {}
    for cell in row:
        cell = cell.strip()
        if MAC_RE.fullmatch(cell):
            d.setdefault("bssid", cell)
        elif cell.isdigit() and 1 <= int(cell) <= 196:
            d.setdefault("channel", int(cell))
        elif cell:
            d.setdefault("ssid", cell)
    return d if d.get("bssid") else None


def sniff_data_frames(iface="wlan1mon", duration=6.0, bpf="type data"):
    """Passively sniff data frames to find (client, bssid) pairs and channels."""
    tcpdump = shutil.which("tcpdump")
    if not tcpdump:
        return [], "tcpdump not installed"
    cmd = [tcpdump, "-i", iface, "-e", "-nn", "-s", "128", "-l", bpf]
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
    except Exception as exc:
        return [], str(exc)
    pairs = []
    deadline = time.time() + duration
    try:
        while time.time() < deadline:
            line = proc.stdout.readline()
            if not line:
                break
            macs = MAC_RE.findall(line)
            if len(macs) >= 2:
                pair = (macs[0].lower().replace("-", ":"),
                        macs[1].lower().replace("-", ":"))
                if pair not in pairs:
                    pairs.append(pair)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
    return [{"client": a, "bssid": b} for a, b in pairs[:40]], ""


def read_dhcp_leases(paths=None):
    """Read (mac, ip) pairs from dnsmasq/udhcpc lease files."""
    if paths is None:
        paths = ["/tmp/dhcp.leases", "/var/lib/misc/dnsmasq.leases",
                 "/tmp/dhcp.leases.wlan0mgmt"]
    leases = {}
    for path in paths:
        try:
            with open(path, errors="replace") as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) >= 3 and MAC_RE.fullmatch(parts[1]):
                        leases[parts[1].lower().replace("-", ":")] = parts[2]
        except Exception:
            continue
    return leases


def is_injectable_target(device):
    """Return (ok, reason) for a candidate target.

    Encodes the hard hardware/regulatory constraints discovered in research.
    """
    channel = device.get("channel")
    if channel is None:
        return False, "unknown channel"
    try:
        ch = int(channel)
    except Exception:
        return False, "bad channel"
    if ch == 14:
        return False, "channel 14 (regulatory)"
    if ch >= 36 and 52 <= ch <= 64:
        return False, "DFS channel (injection blocked)"
    if ch >= 100 and ch <= 144:
        return False, "DFS channel (injection blocked)"
    if ch > 196:
        return False, "6 GHz (injection blocked)"
    sec = str(device.get("security", "")).upper()
    if "WPA3" in sec or "SAE" in sec or "OWE" in sec:
        return False, "WPA3/PMF (injection defeated)"
    return True, "ok"


def sample_targets():
    """Hardware-free sample targets for UI/tests."""
    return [
        {"bssid": "00:11:22:33:44:55", "client": "aa:bb:cc:dd:ee:01",
         "ssid": "LAB-WPA2", "channel": 6, "security": "WPA2-PSK"},
        {"bssid": "00:11:22:33:44:66", "client": "aa:bb:cc:dd:ee:02",
         "ssid": "TEST-NET", "channel": 11, "security": "WPA2-PSK"},
        {"bssid": "00:11:22:33:44:77", "client": "aa:bb:cc:dd:ee:03",
         "ssid": "DFS-NET", "channel": 100, "security": "WPA2-PSK"},
    ]
