#!/usr/bin/env python3
"""Find a reachable UniFi OS console from the Pager.

The Pager must already have L3 reachability -- joined to the target WiFi via
wlan0cli or wired through the USB-C RTL8153 gadget. Discovery is a plain TCP
sweep of 11443 followed by the non-destructive safe probe. No radio involved.
"""

from __future__ import annotations

import ipaddress
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor

from . import net

DEFAULT_PORT = net.DEFAULT_PORT


def local_ips():
    """Best-effort list of local IPv4 addresses (no external deps)."""
    ips = []
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if ip not in ips and not ip.startswith("127."):
                ips.append(ip)
    except Exception:
        pass
    # OpenWrt often resolves the hostname poorly; ask `ip` as a fallback.
    try:
        out = subprocess.check_output(
            ["ip", "-4", "-o", "addr", "show"], text=True, timeout=4)
        for line in out.splitlines():
            parts = line.split()
            for p in parts:
                if "/" in p:
                    ip = p.split("/", 1)[0]
                    if ip not in ips and not ip.startswith("127."):
                        ips.append(ip)
                    break
    except Exception:
        pass
    return ips


def subnets(prefix=24):
    """Return ip_network objects for the local IPv4 subnets."""
    nets = []
    for ip in local_ips():
        try:
            nets.append(ipaddress.ip_network("%s/%d" % (ip, prefix), strict=False))
        except ValueError:
            continue
    return nets


def tcp_open(host, port=DEFAULT_PORT, timeout=0.6):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((str(host), int(port)))
        return True
    except Exception:
        return False
    finally:
        s.close()


def sweep(networks=None, port=DEFAULT_PORT, timeout=0.6, max_hosts=512,
          workers=24):
    """Sweep the local subnet(s) for the UniFi OS port. Returns host strings."""
    nets = networks if networks is not None else subnets()
    hosts = []
    for net in nets:
        for ip in net.hosts():
            hosts.append(str(ip))
            if len(hosts) >= max_hosts:
                break
        if len(hosts) >= max_hosts:
            break
    found = []
    if not hosts:
        return found
    with ThreadPoolExecutor(max_workers=workers) as ex:
        results = ex.map(lambda h: (h, tcp_open(h, port, timeout)), hosts)
        for host, ok in results:
            if ok:
                found.append(host)
    return found


def verify(hosts, port=DEFAULT_PORT, timeout=6.0, tls=True):
    """Run the safe probe against each candidate. Returns enriched dicts."""
    out = []
    for host in hosts:
        verdict = net.safe_probe(host, port, timeout=timeout, tls=tls)
        out.append({
            "host": host,
            "port": port,
            "state": verdict["state"],
            "detail": verdict["detail"],
            "http_status": verdict["http_status"],
            "fingerprint": verdict["fingerprint"],
            "tls": tls,
        })
    return out


def scan(port=DEFAULT_PORT, timeout=6.0, tls=True, max_hosts=512):
    """Full discover: sweep then verify. Returns verified target dicts."""
    return verify(sweep(port=port, max_hosts=max_hosts), port=port,
                  timeout=timeout, tls=tls)


def sample_targets():
    """Hardware-free sample targets for UI/tests. Real verdicts only."""
    return [
        {"host": "192.168.1.10", "port": 11443, "state": "vulnerable",
         "detail": "auth bypass reached the vulnerable handler",
         "fingerprint": True, "tls": True},
        {"host": "192.168.1.20", "port": 11443, "state": "patched",
         "detail": "nginx rejected the divergence (HTTP 400)",
         "fingerprint": True, "tls": True},
        {"host": "192.168.1.30", "port": 11443, "state": "unaffected",
         "detail": "no UniFi OS fingerprint on /",
         "fingerprint": False, "tls": True},
    ]
