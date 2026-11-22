"""Monitor-mode capture and injection for the Pager's MT7921.

FTKRACK uses one interface in monitor mode (normally wlan1mon).  Linux
AF_PACKET SOCK_RAW on that interface gives both sides of the exchange:

    recvfrom() -> radiotap + 802.11 frames from the air
    send()     -> minimal radiotap + 802.11 frame back onto the air

FTKRACK never changes interface mode itself.  The Pineapple must already have
the interface in radiotap monitor mode; we verify that through sysfs and refuse
to proceed otherwise.  Arbitrary data-frame injection is NOT asserted here --
the only frame we ever transmit is a verbatim replay of a captured management
frame, and capability is reported honestly from the actual socket write.

HONESTY
-------
* probe() succeeds only if the interface exists and reports ARPHRD type 803
  (ARPHRD_IEEE80211_RADIOTAP).  No sysfs node => NO MONITOR.
* inject() returns True only when the kernel accepted the whole frame.
* MockInjector exists for the test suite and is never used by payload.sh.
"""

from __future__ import annotations

import os
import socket
from typing import Optional

ETH_P_ALL = 0x0003
ARPHRD_IEEE80211_RADIOTAP = 803


class MonitorError(Exception):
    pass


def interface_type(iface: str) -> Optional[int]:
    path = f"/sys/class/net/{iface}/type"
    try:
        with open(path, "r") as fh:
            return int(fh.read().strip(), 10)
    except (OSError, ValueError):
        return None


def is_monitor(iface: str) -> bool:
    """True only for a sysfs-visible radiotap monitor interface."""
    return interface_type(iface) == ARPHRD_IEEE80211_RADIOTAP


def find_monitor(preferred: tuple[str, ...] = ("wlan1mon", "wlan0mon")) -> Optional[str]:
    for iface in preferred:
        if is_monitor(iface):
            return iface
    try:
        names = sorted(os.listdir("/sys/class/net"))
    except OSError:
        return None
    for name in names:
        if name.endswith("mon") and is_monitor(name):
            return name
    return None


class MonitorInjector:
    capability = "monitor"

    def __init__(self, iface: str = "wlan1mon", timeout_s: float = 0.25):
        self.iface = iface
        self.timeout_s = timeout_s
        self.sock: Optional[socket.socket] = None
        self.path = f"/sys/class/net/{iface}/type"

    def probe(self) -> bool:
        return is_monitor(self.iface)

    def open(self) -> None:
        if not self.probe():
            raise MonitorError(
                f"{self.iface} is not a radiotap monitor interface "
                "(expected ARPHRD type 803)")
        try:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                      socket.htons(ETH_P_ALL))
            self.sock.bind((self.iface, 0))
            self.sock.settimeout(self.timeout_s)
        except OSError as exc:
            if self.sock is not None:
                self.sock.close()
                self.sock = None
            raise MonitorError(f"cannot open {self.iface}: {exc}") from exc

    def recv_frame(self) -> Optional[bytes]:
        if self.sock is None:
            return None
        try:
            data, _addr = self.sock.recvfrom(4096)
            return bytes(data)
        except socket.timeout:
            return None
        except OSError:
            return None

    def inject(self, frame: bytes) -> bool:
        if self.sock is None:
            return False
        try:
            return self.sock.send(frame) == len(frame)
        except OSError:
            return False

    def close(self) -> None:
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None


class MockInjector:
    """Hardware-free injector.  feeds is a list of raw capture buffers."""

    capability = "mock"

    def __init__(self, feeds=None, inject_ok: bool = True):
        self.feeds = list(feeds or [])
        self.inject_ok = inject_ok
        self.injected: list[bytes] = []
        self.sock = object()

    def probe(self) -> bool:
        return True

    def open(self) -> None:
        return None

    def recv_frame(self) -> Optional[bytes]:
        return self.feeds.pop(0) if self.feeds else None

    def inject(self, frame: bytes) -> bool:
        if self.inject_ok:
            self.injected.append(bytes(frame))
        return self.inject_ok

    def close(self) -> None:
        return None
